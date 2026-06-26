use std::time::Duration;
use reqwest::{Client, multipart};
use serde::de::DeserializeOwned;
use serde_json::json;

use crate::error::HarborError;
use crate::types::{
    BucketListResponse, BucketResponse, BucketSummary, FileListResponse, FileSummary,
    FinalizeResponse, HarborErrorBody, ReserveResponse, SpaceListItem, SpaceListResponse,
    StatusResponse, UploadResponse,
};

pub struct HarborClientOptions {
    pub api_key: String,
    pub base_url: String,
    pub upload_max_retries: u32,
    pub upload_retry_delay: Duration,
    pub poll_delay: Duration,
    pub poll_max_attempts: u32,
}

impl Default for HarborClientOptions {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            base_url: "https://api.testnet.harbor.walrus.xyz".to_string(),
            upload_max_retries: 20,
            upload_retry_delay: Duration::from_millis(3000),
            poll_delay: Duration::from_millis(1500),
            poll_max_attempts: 60,
        }
    }
}

pub struct HarborClient {
    client: Client,
    options: HarborClientOptions,
}

impl HarborClient {
    pub fn new(options: HarborClientOptions) -> Self {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", options.api_key))
                .expect("Invalid API key header value"),
        );

        let client = Client::builder()
            .default_headers(headers)
            .build()
            .expect("Failed to build reqwest client");

        Self { client, options }
    }

    async fn handle_response<T: DeserializeOwned>(res: reqwest::Response) -> Result<T, HarborError> {
        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_else(|_| "<unreadable body>".to_string());
            let parsed: Option<HarborErrorBody> = serde_json::from_str(&body).ok();
            let code = parsed.as_ref().and_then(|p| p.code.clone());
            return Err(HarborError::Http { status, message: body, code });
        }
        res.json::<T>().await.map_err(Into::into)
    }

    pub async fn list_spaces(&self) -> Result<Vec<SpaceListItem>, HarborError> {
        let url = format!("{}/api/v1/spaces", self.options.base_url);
        let res = self.client.get(&url).send().await?;
        let body: SpaceListResponse = Self::handle_response(res).await?;
        Ok(body.data)
    }

    pub async fn list_buckets(&self, space_id: &str) -> Result<Vec<BucketSummary>, HarborError> {
        let url = format!("{}/api/v1/spaces/{}/buckets", self.options.base_url, space_id);
        let res = self.client.get(&url).send().await?;
        let body: BucketListResponse = Self::handle_response(res).await?;
        Ok(body.buckets)
    }

    pub async fn get_bucket(&self, bucket_id: &str) -> Result<BucketSummary, HarborError> {
        let url = format!("{}/api/v1/buckets/{}", self.options.base_url, bucket_id);
        let res = self.client.get(&url).send().await?;
        let body: BucketResponse = Self::handle_response(res).await?;
        Ok(body.data)
    }

    pub async fn reserve_bucket(&self, space_id: &str, name: &str) -> Result<ReserveResponse, HarborError> {
        let url = format!("{}/api/v1/spaces/{}/buckets", self.options.base_url, space_id);
        let payload = json!({ "name": name, "scope": "private" });
        let res = self.client.post(&url).json(&payload).send().await?;
        Self::handle_response(res).await
    }

    pub async fn finalize_bucket(&self, bucket_id: &str, signature: &str) -> Result<FinalizeResponse, HarborError> {
        let url = format!("{}/api/v1/buckets/{}/finalize", self.options.base_url, bucket_id);
        let payload = json!({ "signature": signature });
        let res = self.client.post(&url).json(&payload).send().await?;
        Self::handle_response(res).await
    }

    pub async fn delete_bucket(&self, bucket_id: &str) -> Result<(), HarborError> {
        let url = format!("{}/api/v1/buckets/{}?confirm=true", self.options.base_url, bucket_id);
        let res = self.client.delete(&url).send().await?;
        if res.status() == reqwest::StatusCode::NO_CONTENT {
            Ok(())
        } else {
            let status = res.status();
            let body = res.text().await.unwrap_or_else(|_| "".to_string());
            let parsed: Option<HarborErrorBody> = serde_json::from_str(&body).ok();
            let code = parsed.as_ref().and_then(|p| p.code.clone());
            Err(HarborError::Http { status, message: body, code })
        }
    }

    pub async fn list_files(&self, bucket_id: &str) -> Result<Vec<FileSummary>, HarborError> {
        let url = format!("{}/api/v1/buckets/{}/files", self.options.base_url, bucket_id);
        let res = self.client.get(&url).send().await?;
        let body: FileListResponse = Self::handle_response(res).await?;
        Ok(body.data)
    }

    pub async fn upload_file(
        &self,
        bucket_id: &str,
        file_name: &str,
        ciphertext: Vec<u8>,
        mut on_retry: impl FnMut(u32, &str),
    ) -> Result<UploadResponse, HarborError> {
        let url = format!("{}/api/v1/buckets/{}/files", self.options.base_url, bucket_id);
        
        for attempt in 1..=self.options.upload_max_retries {
            let part = multipart::Part::bytes(ciphertext.clone())
                .file_name(file_name.to_string())
                .mime_str("application/octet-stream")
                .unwrap();
            
            let form = multipart::Form::new()
                .part("file", part)
                .text("name", file_name.to_string());

            let res = self.client.post(&url).multipart(form).send().await?;
            if res.status().is_success() {
                return res.json::<UploadResponse>().await.map_err(Into::into);
            }

            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            let parsed: Option<HarborErrorBody> = serde_json::from_str(&body).ok();

            if status == reqwest::StatusCode::FORBIDDEN {
                if let Some(ref p) = parsed {
                    if p.code.as_deref() == Some("mirror_missing_grant") {
                        on_retry(attempt, &body);
                        tokio::time::sleep(self.options.upload_retry_delay).await;
                        continue;
                    }
                }
            }

            return Err(HarborError::Http { 
                status, 
                message: body, 
                code: parsed.and_then(|p| p.code) 
            });
        }

        Err(HarborError::Timeout(format!("Upload failed after {} attempts", self.options.upload_max_retries)))
    }

    pub async fn get_file_status(&self, bucket_id: &str, file_id: &str) -> Result<StatusResponse, HarborError> {
        let url = format!("{}/api/v1/buckets/{}/files/{}/status", self.options.base_url, bucket_id, file_id);
        let res = self.client.get(&url).send().await?;
        Self::handle_response(res).await
    }

    pub async fn poll_until_completed(
        &self,
        bucket_id: &str,
        file_id: &str,
        mut on_tick: impl FnMut(u32, &str),
    ) -> Result<(), HarborError> {
        for attempt in 1..=self.options.poll_max_attempts {
            let status = self.get_file_status(bucket_id, file_id).await?;
            on_tick(attempt, &status.data.state);
            
            if status.data.state == "completed" {
                return Ok(());
            }
            if status.data.state == "failed" {
                let err_msg = status.data.error.map(|e| e.message).unwrap_or_default();
                return Err(HarborError::Http {
                    status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                    message: format!("Upload failed: {}", err_msg),
                    code: None,
                });
            }
            tokio::time::sleep(self.options.poll_delay).await;
        }
        Err(HarborError::Timeout("File did not reach completed state in time".to_string()))
    }

    pub async fn download_file(&self, bucket_id: &str, file_id: &str) -> Result<Vec<u8>, HarborError> {
        let url = format!("{}/api/v1/buckets/{}/files/{}/download", self.options.base_url, bucket_id, file_id);
        let res = self.client.get(&url).send().await?;
        if res.status().is_success() {
            let bytes = res.bytes().await?;
            Ok(bytes.to_vec())
        } else {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            Err(HarborError::Http { status, message: body, code: None })
        }
    }

    pub async fn delete_file(&self, bucket_id: &str, file_id: &str) -> Result<(), HarborError> {
        let url = format!("{}/api/v1/buckets/{}/files/{}", self.options.base_url, bucket_id, file_id);
        let res = self.client.delete(&url).send().await?;
        if res.status() == reqwest::StatusCode::NO_CONTENT {
            Ok(())
        } else {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            Err(HarborError::Http { status, message: body, code: None })
        }
    }
}
