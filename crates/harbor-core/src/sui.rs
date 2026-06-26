use std::collections::HashMap;
use std::str::FromStr;

use async_trait::async_trait;
use futures::StreamExt;
use futures::pin_mut;
use seal_sdk_rs::base_client::KeyServerInfo;
use seal_sdk_rs::base_client::PartialKeyServer;
use seal_sdk_rs::base_client::ServerType;
use seal_sdk_rs::error::SealClientError;
use seal_sdk_rs::generic_types::BCSSerializableProgrammableTransaction;
use seal_sdk_rs::generic_types::ObjectID;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::ListDynamicFieldsRequest;
use sui_sdk_types::Address;
use sui_sdk_types::Argument;
use sui_sdk_types::Command;
use sui_sdk_types::Identifier;
use sui_sdk_types::Input;
use sui_sdk_types::MoveCall;
use sui_sdk_types::ProgrammableTransaction;
use sui_sdk_types::SharedInput;

use crate::error::HarborError;

#[derive(Clone)]
pub struct CurrentSuiClientAdapter {
    client: sui_rpc::Client,
}

impl CurrentSuiClientAdapter {
    pub fn new(client: sui_rpc::Client) -> Self {
        Self { client }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
struct KeyServerV1 {
    name: String,
    url: String,
    #[allow(dead_code)]
    key_type: u8,
    pk: Vec<u8>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct KeyServerV2 {
    name: String,
    #[allow(dead_code)]
    key_type: u8,
    pk: Vec<u8>,
    server_type: MoveServerType,
}

#[derive(Debug, Clone, serde::Deserialize)]
enum MoveServerType {
    Independent {
        url: String,
    },
    Committee {
        version: u32,
        threshold: u16,
        partial_key_servers: Vec<MovePartialKeyServer>,
    },
}

#[derive(Debug, Clone, serde::Deserialize)]
struct MovePartialKeyServer {
    name: String,
    url: String,
    partial_pk: Vec<u8>,
    party_id: u16,
}

#[async_trait]
impl seal_sdk_rs::sui_client::SuiClient for CurrentSuiClientAdapter {
    type Error = SealClientError;

    async fn get_key_server_info(
        &self,
        key_server_id: [u8; 32],
    ) -> Result<KeyServerInfo, Self::Error> {
        let object_id = Address::new(key_server_id);
        let fields = self.list_dynamic_fields(object_id).await?;

        if let Some(value) = fields.get(&2) {
            let key_server: KeyServerV2 = bcs::from_bytes(value)?;
            return Ok(KeyServerInfo {
                object_id: ObjectID(key_server_id),
                name: key_server.name,
                public_key: hex::encode(key_server.pk),
                server_type: match key_server.server_type {
                    MoveServerType::Independent { url } => ServerType::Independent { url },
                    MoveServerType::Committee {
                        version,
                        threshold,
                        partial_key_servers,
                    } => ServerType::Committee {
                        version,
                        threshold,
                        partial_key_servers: partial_key_servers
                            .into_iter()
                            .map(|entry| PartialKeyServer {
                                name: entry.name,
                                url: entry.url,
                                partial_pk: entry.partial_pk,
                                party_id: entry.party_id,
                            })
                            .collect(),
                    },
                },
            });
        }

        if let Some(value) = fields.get(&1) {
            let key_server: KeyServerV1 = bcs::from_bytes(value)?;
            return Ok(KeyServerInfo {
                object_id: ObjectID(key_server_id),
                name: key_server.name,
                public_key: hex::encode(key_server.pk),
                server_type: ServerType::Independent {
                    url: key_server.url,
                },
            });
        }

        Err(seal_client_error(format!(
            "missing KeyServer dynamic field for {object_id}"
        )))
    }
}

impl CurrentSuiClientAdapter {
    async fn list_dynamic_fields(
        &self,
        parent: Address,
    ) -> Result<HashMap<u64, bytes::Bytes>, SealClientError> {
        let mut request = ListDynamicFieldsRequest::default();
        request.parent = Some(parent.to_string());
        request.page_size = Some(10);
        request.read_mask = Some(FieldMask::from_str("*"));
        let stream = self.client.list_dynamic_fields(request);
        pin_mut!(stream);
        let mut fields = HashMap::new();
        while let Some(field) = stream.next().await {
            let field = field.map_err(|error| seal_client_error(error.to_string()))?;
            let name = field
                .name
                .and_then(|name| name.value)
                .ok_or_else(|| seal_client_error("dynamic field name missing"))?;
            let value = field
                .value
                .and_then(|value| value.value)
                .ok_or_else(|| seal_client_error("dynamic field value missing"))?;
            let key = bcs::from_bytes::<u64>(&name)?;
            fields.insert(key, value);
        }
        Ok(fields)
    }
}

#[derive(Clone, Debug)]
pub struct ApprovalPtb(pub ProgrammableTransaction);

impl BCSSerializableProgrammableTransaction for ApprovalPtb {
    fn to_bcs_bytes(&self) -> Result<Vec<u8>, seal_sdk_rs::error::SealClientError> {
        bcs::to_bytes(&self.0).map_err(Into::into)
    }
}

pub fn build_seal_approve_ptb(
    package_id: Address,
    seal_policy_id: Address,
    seal_policy_initial_shared_version: u64,
    id_bytes: Vec<u8>,
) -> Result<ApprovalPtb, HarborError> {
    let inputs = vec![
        Input::Pure(bcs::to_bytes(&id_bytes).map_err(|e| HarborError::sui(e.to_string()))?),
        Input::Shared(SharedInput::new(
            seal_policy_id,
            seal_policy_initial_shared_version,
            false,
        )),
    ];
    let command = Command::MoveCall(MoveCall {
        package: package_id,
        module: Identifier::from_str("bucket_policy")
            .map_err(|error| HarborError::sui(error.to_string()))?,
        function: Identifier::from_str("seal_approve")
            .map_err(|error| HarborError::sui(error.to_string()))?,
        type_arguments: Vec::new(),
        arguments: vec![Argument::Input(0), Argument::Input(1)],
    });

    Ok(ApprovalPtb(ProgrammableTransaction {
        inputs,
        commands: vec![command],
    }))
}

fn seal_client_error(message: impl Into<String>) -> SealClientError {
    SealClientError::CannotUnwrapTypedError {
        error_message: message.into(),
    }
}
