use std::collections::HashMap;
use std::str::FromStr;

use async_trait::async_trait;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::traits::Signer;
use rand::RngCore;
use seal_sdk_rs::base_client::{BaseSealClient, KeyServerConfig};
use seal_sdk_rs::cache::NoCache;
use seal_sdk_rs::error::SealClientError;
use seal_sdk_rs::generic_types::ObjectID;
use sui_sdk_types::Address;

use crate::error::HarborError;
use crate::sui::{CurrentSuiClientAdapter, build_seal_approve_ptb};

#[derive(Clone)]
pub struct SealReqwestClient {
    client: reqwest::Client,
}

impl SealReqwestClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

impl Default for SealReqwestClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl seal_sdk_rs::http_client::HttpClient for SealReqwestClient {
    type PostError = SealClientError;

    async fn post<S: ToString + Send + Sync>(
        &self,
        url: &str,
        headers: HashMap<String, String>,
        body: S,
    ) -> Result<seal_sdk_rs::http_client::PostResponse, Self::PostError> {
        let mut request = self.client.post(url);
        for (key, value) in headers {
            request = request.header(&key, &value);
        }

        let response = request
            .body(body.to_string())
            .send()
            .await
            .map_err(|error| SealClientError::CannotUnwrapTypedError {
                error_message: error.to_string(),
            })?;

        let status = response.status().as_u16();
        let text =
            response
                .text()
                .await
                .map_err(|error| SealClientError::CannotUnwrapTypedError {
                    error_message: error.to_string(),
                })?;

        Ok(seal_sdk_rs::http_client::PostResponse { status, text })
    }
}

type HarborSealClient = BaseSealClient<
    NoCache<seal_sdk_rs::cache_key::KeyServerInfoCacheKey, seal_sdk_rs::base_client::KeyServerInfo>,
    NoCache<seal_sdk_rs::cache_key::DerivedKeyCacheKey, seal_sdk_rs::base_client::DerivedKeys>,
    SealClientError,
    CurrentSuiClientAdapter,
    SealClientError,
    SealReqwestClient,
>;

pub struct HarborSealService {
    client: HarborSealClient,
    key_servers: Vec<KeyServerConfig>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SealIdentity {
    policy_object_id: Address,
    nonce: [u8; 32],
}

impl HarborSealService {
    pub fn new(sui_client: sui_rpc::Client, key_server_ids: Vec<&str>) -> Self {
        let sui_adapter = CurrentSuiClientAdapter::new(sui_client);
        let http_client = SealReqwestClient::new();
        let key_servers: Vec<KeyServerConfig> = key_server_ids
            .into_iter()
            .map(|id| {
                KeyServerConfig::new(
                    ObjectID(
                        Address::from_str(id)
                            .expect("invalid key server id")
                            .into_inner(),
                    ),
                    None,
                )
            })
            .collect();

        let client = BaseSealClient::new_custom(
            NoCache::default(),
            NoCache::default(),
            sui_adapter,
            http_client,
        );

        Self {
            client,
            key_servers,
        }
    }

    pub async fn encrypt(
        &self,
        package_id: &str,
        policy_id: &str,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), HarborError> {
        let policy_address =
            Address::from_str(policy_id).map_err(|e| HarborError::seal(e.to_string()))?;
        let package_address =
            Address::from_str(package_id).map_err(|e| HarborError::seal(e.to_string()))?;

        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);

        let identity = SealIdentity {
            policy_object_id: policy_address,
            nonce,
        };

        let id_bytes = bcs::to_bytes(&identity).map_err(|e| HarborError::seal(e.to_string()))?;

        let (encrypted, _) = self
            .client
            .encrypt_bytes(
                ObjectID(package_address.into_inner()),
                id_bytes.clone(),
                1,
                self.key_servers.clone(),
                plaintext.to_vec(),
            )
            .await
            .map_err(|e| HarborError::seal(e.to_string()))?;

        let encrypted_bytes =
            bcs::to_bytes(&encrypted).map_err(|e| HarborError::seal(e.to_string()))?;

        Ok((id_bytes, encrypted_bytes))
    }

    pub async fn decrypt(
        &self,
        package_id: &str,
        policy_id: &str,
        policy_initial_shared_version: u64,
        id_bytes: Vec<u8>,
        ciphertext: &[u8],
        session_key: &seal_sdk_rs::session_key::SessionKey,
    ) -> Result<Vec<u8>, HarborError> {
        let policy_address =
            Address::from_str(policy_id).map_err(|e| HarborError::seal(e.to_string()))?;
        let package_address =
            Address::from_str(package_id).map_err(|e| HarborError::seal(e.to_string()))?;

        let approval_ptb = build_seal_approve_ptb(
            package_address,
            policy_address,
            policy_initial_shared_version,
            id_bytes,
        )?;

        let refs = vec![ciphertext];

        let aggregator_urls = HashMap::new();

        let mut results = self
            .client
            .decrypt_multiple_objects_bytes(&refs, approval_ptb, session_key, aggregator_urls)
            .await
            .map_err(|e| HarborError::seal(e.to_string()))?;

        results
            .pop()
            .ok_or_else(|| HarborError::seal("No decrypted data returned"))
    }
}

pub fn sign_reserve_bytes(
    keypair: &Ed25519KeyPair,
    base64_bytes: &str,
) -> Result<String, HarborError> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use fastcrypto::hash::{Blake2b256, HashFunction};
    use fastcrypto::traits::KeyPair;

    let bytes = STANDARD
        .decode(base64_bytes)
        .map_err(|e| HarborError::seal(e.to_string()))?;

    let mut message = vec![0, 0, 0];
    message.extend_from_slice(&bytes);

    let hash = Blake2b256::digest(&message);
    let sig = keypair.sign(&hash.digest);

    let mut full_sig = vec![0x00];
    full_sig.extend_from_slice(sig.as_ref());
    full_sig.extend_from_slice(keypair.public().as_ref());

    Ok(STANDARD.encode(&full_sig))
}
