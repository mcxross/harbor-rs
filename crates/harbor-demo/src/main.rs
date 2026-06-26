use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use std::str::FromStr;

use harbor_core::client::{HarborClient, HarborClientOptions};
use harbor_core::seal::{sign_reserve_bytes, HarborSealService};
use seal_sdk_rs::session_key::SessionKey;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::traits::ToFromBytes;

const ORIGINAL_PACKAGE_ID: &str = "0x8b2429358e9b0f005b69fe8ad3cbd1268ad87f35047a21612e082c64824faf8d";
const LATEST_PACKAGE_ID: &str = "0xc11d875481544e9b6c616f7d6704266e1633b4034eab7ed76626dc25ebfcd506";
const SEAL_KEY_SERVER_OBJECT_IDS: &[&str] = &[
    "0x6068c0acb197dddbacd4746a9de7f025b2ed5a5b6c1b1ab44dade4426d141da2",
    "0x164ac3d2b3b8694b8181c13f671950004765c23f270321a45fdd04d40cccf0f2",
    "0x9c949e53c36ab7a9c484ed9e8b43267a77d4b8d70e79aa6b39042e3d4c434105",
];
const SUI_RPC_URL: &str = "https://fullnode.testnet.sui.io:443";
use harbor_core::utils::{fetch_initial_shared_version, SimpleSigner};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("Harbor RS Quickstart Round Trip");

    let api_key = env::var("HARBOR_API_KEY").expect("HARBOR_API_KEY must be set");
    let privkey_b64 = env::var("HARBOR_SERVICE_PRIVKEY").expect("HARBOR_SERVICE_PRIVKEY must be set");
    
    let keypair = if privkey_b64.starts_with("suiprivkey") {
        let (_, data) = bech32::decode(&privkey_b64).expect("Invalid bech32");
        let secret_key = data[1..].to_vec(); // Skip the 1-byte flag (0x00 for ed25519)
        Ed25519KeyPair::from_bytes(&secret_key).expect("Invalid ed25519 key")
    } else {
        let privkey_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            privkey_b64,
        ).expect("Invalid base64");
        Ed25519KeyPair::from_bytes(&privkey_bytes).expect("Invalid ed25519 key")
    };

    let harbor = HarborClient::new(HarborClientOptions {
        api_key,
        ..Default::default()
    });

    let sui_client = sui_rpc::Client::new(SUI_RPC_URL)?;
    let seal = HarborSealService::new(sui_client, SEAL_KEY_SERVER_OBJECT_IDS.to_vec());

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let bucket_name = format!("round-trip-{}", now);
    let upload_name = "sample.txt.enc";
    let plaintext = b"Hello Harbor from Rust!";

    // Step 1: List spaces
    println!("\n[1/10] List spaces");
    let spaces = harbor.list_spaces().await?;
    let space = spaces.first().expect("No spaces found for this API key.");
    println!("  space.id={}", space.id);

    // Step 2: Reserve a private bucket
    println!("\n[2/10] Reserve a private bucket");
    let reserved = harbor.reserve_bucket(&space.id, &bucket_name).await?;
    println!("  bucket_id={} digest={}", reserved.bucket_id, reserved.digest);

    // Step 3: Sign reserve bytes
    println!("\n[3/10] Sign reserve bytes with service key");
    let signature = sign_reserve_bytes(&keypair, &reserved.bytes)?;
    println!("  signature.length={}", signature.len());

    // Step 4: Finalize
    println!("\n[4/10] Finalize");
    let finalized = harbor.finalize_bucket(&reserved.bucket_id, &signature).await?;
    println!("  seal_policy_id={} state={}", finalized.seal_policy_id, finalized.state);

    // Step 5: Encrypt payload
    println!("\n[5/10] Encrypt sample.txt with Seal");
    let (id_bytes, ciphertext) = seal.encrypt(
        ORIGINAL_PACKAGE_ID,
        &finalized.seal_policy_id,
        plaintext,
    ).await?;
    println!("  plaintext={}B ciphertext={}B", plaintext.len(), ciphertext.len());

    // Step 6: Upload
    println!("\n[6/10] Upload");
    let upload = harbor.upload_file(
        &reserved.bucket_id,
        upload_name,
        ciphertext,
        |attempt, body| println!("  attempt {}: mirror_missing_grant - {}", attempt, body),
    ).await?;
    println!("  uploaded file.id={}", upload.data.id);

    // Step 7: Poll status
    println!("\n[7/10] Poll status until completed");
    harbor.poll_until_completed(
        &reserved.bucket_id,
        &upload.data.id,
        |attempt, state| println!("  attempt {}: state={}", attempt, state),
    ).await?;

    // Step 8: Download
    println!("\n[8/10] Download ciphertext");
    let downloaded = harbor.download_file(&reserved.bucket_id, &upload.data.id).await?;
    println!("  downloaded {}B", downloaded.len());

    // Fetch initial shared version for policy
    println!("\n[9/10] Decrypt with Seal");
    let mut sui_client_for_version = sui_rpc::Client::new(SUI_RPC_URL)?;
    let policy_initial_shared_version = fetch_initial_shared_version(&mut sui_client_for_version, &finalized.seal_policy_id).await?;
    println!("  policy_initial_shared_version={}", policy_initial_shared_version);

    let mut signer = SimpleSigner(keypair);
    let pkg_addr = sui_sdk_types::Address::from_str(ORIGINAL_PACKAGE_ID).unwrap().into_inner();
    let session_key = SessionKey::new(
        pkg_addr,
        10,
        &mut signer,
    ).await.expect("Failed to create session key");

    let decrypted = seal.decrypt(
        LATEST_PACKAGE_ID,
        &finalized.seal_policy_id,
        policy_initial_shared_version,
        id_bytes,
        &downloaded,
        &session_key,
    ).await?;
    println!("  decrypted {}B", decrypted.len());

    // Step 10: Verify + delete
    println!("\n[10/10] Verify + delete");
    let matches = decrypted == plaintext;
    println!("  {}", if matches { "MATCH" } else { "MISMATCH" });

    harbor.delete_file(&reserved.bucket_id, &upload.data.id).await?;
    println!("  deleted file.id={}", upload.data.id);

    println!("\nRound-trip OK.");

    if !matches {
        std::process::exit(1);
    }

    Ok(())
}
