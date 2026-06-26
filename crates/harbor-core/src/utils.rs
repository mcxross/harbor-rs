use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::traits::KeyPair;
use fastcrypto::traits::Signer;
use fastcrypto::hash::{HashFunction, Blake2b256};
use sui_sdk_types::Address;
use seal_sdk_rs::error::SessionKeyError;
use seal_sdk_rs::generic_types::SuiAddress;
use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;
use sui_rpc::field::FieldMaskUtil;

/// Helper function to fetch the `initial_shared_version` for a shared object on Sui.
pub async fn fetch_initial_shared_version(client: &mut sui_rpc::Client, object_id: &str) -> anyhow::Result<u64> {
    let mut request = GetObjectRequest::default();
    request.object_id = Some(object_id.to_string());
    request.read_mask = Some(sui_rpc::field::FieldMask::from_str("*"));
    
    let response = client.ledger_client().get_object(request).await?.into_inner();
    let object = response.object.ok_or_else(|| anyhow::anyhow!("Object not found in response"))?;
    let owner = object.owner.ok_or_else(|| anyhow::anyhow!("No owner in object"))?;
    
    owner.version.ok_or_else(|| anyhow::anyhow!("No initial_shared_version found for object"))
}

/// A simple implementation of the `seal_sdk_rs::signer::Signer` trait which wraps an `Ed25519KeyPair`.
/// It implements the necessary Sui Intent (PersonalMessage) BCS serialization and Blake2b256 hashing
/// before signing, allowing it to easily interact with Harbor KeyServers.
pub struct SimpleSigner(pub Ed25519KeyPair);

#[async_trait::async_trait]
impl seal_sdk_rs::signer::Signer for SimpleSigner {
    type Error = SessionKeyError;
    
    fn get_sui_address(&mut self) -> Result<SuiAddress, Self::Error> {
        let pub_key = self.0.public();
        let mut bytes = vec![0x00];
        bytes.extend_from_slice(pub_key.as_ref());
        let hash = Blake2b256::digest(&bytes);
        let addr = Address::new(hash.digest);
        Ok(SuiAddress(addr.into_inner()))
    }
    
    fn get_public_key(&mut self) -> Result<fastcrypto::ed25519::Ed25519PublicKey, Self::Error> {
        Ok(self.0.public().clone())
    }
    
    async fn sign_personal_message(&mut self, data: Vec<u8>) -> Result<fastcrypto::ed25519::Ed25519Signature, Self::Error> {
        // Construct the IntentMessage for PersonalMessage
        // Intent is [3, 0, 0] (Scope::PersonalMessage, Version::V0, AppId::Sui)
        let mut intent_msg = vec![3, 0, 0];
        
        // Serialize the data as a BCS byte array (ULEB128 length followed by bytes)
        let mut len = data.len();
        loop {
            let mut byte = (len & 0x7F) as u8;
            len >>= 7;
            if len != 0 {
                byte |= 0x80;
            }
            intent_msg.push(byte);
            if len == 0 {
                break;
            }
        }
        intent_msg.extend_from_slice(&data);
        
        let hash = Blake2b256::digest(&intent_msg);
        Ok(self.0.sign(&hash.digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::ed25519::Ed25519KeyPair;
    use fastcrypto::traits::{KeyPair, VerifyingKey};
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use seal_sdk_rs::signer::Signer as SealSigner;

    #[tokio::test]
    async fn test_simple_signer_sui_intent_format() {
        let mut rng = StdRng::from_seed([0; 32]);
        let keypair = Ed25519KeyPair::generate(&mut rng);
        let pub_key = keypair.public().clone();
        
        let mut signer = SimpleSigner(keypair);

        let message = b"hello harbor node".to_vec();
        
        // Compute what we expect
        let mut expected_intent = vec![3, 0, 0];
        // ULEB128 of 17 (0x11)
        expected_intent.push(17);
        expected_intent.extend_from_slice(b"hello harbor node");
        
        let hash = Blake2b256::digest(&expected_intent);

        let actual_signature = signer.sign_personal_message(message).await.unwrap();

        // Verify the signature against the expected hash using the public key
        // Wait, fastcrypto signature verification takes the raw message, but Ed25519 usually takes the message not the hash.
        // Wait! Ed25519KeyPair::sign in fastcrypto signs the literal bytes passed to it. In this case, hash.digest.
        assert!(pub_key.verify(&hash.digest, &actual_signature).is_ok());
    }

    #[test]
    fn test_simple_signer_address_derivation() {
        let mut rng = StdRng::from_seed([0; 32]);
        let keypair = Ed25519KeyPair::generate(&mut rng);
        let pub_key = keypair.public().clone();
        
        let mut signer = SimpleSigner(keypair);
        
        let addr = signer.get_sui_address().unwrap();
        
        let mut bytes = vec![0x00];
        bytes.extend_from_slice(pub_key.as_ref());
        let hash = Blake2b256::digest(&bytes);
        let expected_addr = Address::new(hash.digest);
        
        assert_eq!(addr.0, expected_addr.into_inner());
    }
}
