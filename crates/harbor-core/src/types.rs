use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct SpaceListItem {
    pub id: String,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BucketSummary {
    pub id: String,
    pub name: String,
    pub visibility: String,
    pub state: String,
    pub seal_policy_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FileSummary {
    pub id: String,
    pub name: Option<String>,
    pub size: Option<u64>,
    pub created_at: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ReserveResponse {
    pub bucket_id: String,
    pub bytes: String,
    pub digest: String,
    pub state: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FinalizeResponse {
    pub bucket_id: String,
    pub seal_policy_id: String,
    pub state: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UploadResponseData {
    pub id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UploadResponse {
    pub data: UploadResponseData,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StatusError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StatusResponseData {
    pub state: String,
    pub error: Option<StatusError>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StatusResponse {
    pub data: StatusResponseData,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HarborErrorBody {
    pub code: Option<String>,
    pub error: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SpaceListResponse {
    pub data: Vec<SpaceListItem>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BucketListResponse {
    pub buckets: Vec<BucketSummary>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BucketResponse {
    pub data: BucketSummary,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FileListResponse {
    pub data: Vec<FileSummary>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_space_list() {
        let json = r#"
        {
            "data": [
                {
                    "id": "acddd7dc-0605-4fde-a9a0-36e87053a7ea",
                    "name": "default"
                }
            ]
        }
        "#;
        let parsed: SpaceListResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.data.len(), 1);
        assert_eq!(parsed.data[0].id, "acddd7dc-0605-4fde-a9a0-36e87053a7ea");
        assert_eq!(parsed.data[0].name.as_deref(), Some("default"));
    }

    #[test]
    fn test_deserialize_bucket_summary() {
        let json = r#"
        {
            "data": {
                "id": "30275ac3-fa62-4533-b623-ec84d092be00",
                "name": "test-bucket",
                "visibility": "private",
                "state": "active",
                "seal_policy_id": "0xad0bdff805cd6f8c32b3f74ed979bcb66852ed2168a8954cbbdf7e26cfae4ef4"
            }
        }
        "#;
        let parsed: BucketResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.data.id, "30275ac3-fa62-4533-b623-ec84d092be00");
        assert_eq!(parsed.data.name, "test-bucket");
        assert_eq!(parsed.data.state, "active");
        assert_eq!(
            parsed.data.seal_policy_id.as_deref(),
            Some("0xad0bdff805cd6f8c32b3f74ed979bcb66852ed2168a8954cbbdf7e26cfae4ef4")
        );
    }

    #[test]
    fn test_deserialize_file_summary() {
        let json = r#"
        {
            "data": [
                {
                    "id": "30858fef-1222-4525-8bd6-4857ab0be998",
                    "name": "sample.txt",
                    "size": 467,
                    "created_at": "2026-06-26T13:09:44Z"
                }
            ]
        }
        "#;
        let parsed: FileListResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.data.len(), 1);
        assert_eq!(parsed.data[0].id, "30858fef-1222-4525-8bd6-4857ab0be998");
        assert_eq!(parsed.data[0].size, Some(467));
    }

    #[test]
    fn test_deserialize_upload_response() {
        let json = r#"
        {
            "data": {
                "id": "b69f0440-e8a4-4c62-bfa0-54216d78ecf2"
            }
        }
        "#;
        let parsed: UploadResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.data.id, "b69f0440-e8a4-4c62-bfa0-54216d78ecf2");
    }

    #[test]
    fn test_deserialize_status_response_completed() {
        let json = r#"
        {
            "data": {
                "state": "completed",
                "error": null
            }
        }
        "#;
        let parsed: StatusResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.data.state, "completed");
        assert!(parsed.data.error.is_none());
    }

    #[test]
    fn test_deserialize_status_response_error() {
        let json = r#"
        {
            "data": {
                "state": "failed",
                "error": {
                    "code": "timeout",
                    "message": "Operation timed out"
                }
            }
        }
        "#;
        let parsed: StatusResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.data.state, "failed");
        let error = parsed.data.error.expect("Expected error");
        assert_eq!(error.code, "timeout");
        assert_eq!(error.message, "Operation timed out");
    }
}
