use thiserror::Error;

#[derive(Error, Debug)]
pub enum HarborError {
    #[error("HTTP error ({status}): {message}")]
    Http {
        status: reqwest::StatusCode,
        message: String,
        code: Option<String>,
    },

    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Seal error: {0}")]
    Seal(String),

    #[error("Sui error: {0}")]
    Sui(String),

    #[error("Timeout: {0}")]
    Timeout(String),
}

impl HarborError {
    pub fn seal(msg: impl Into<String>) -> Self {
        Self::Seal(msg.into())
    }

    pub fn sui(msg: impl Into<String>) -> Self {
        Self::Sui(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_harbor_error_display() {
        let err = HarborError::Http {
            status: reqwest::StatusCode::FORBIDDEN,
            message: "Missing grant".to_string(),
            code: Some("mirror_missing_grant".to_string()),
        };
        assert_eq!(err.to_string(), "HTTP error (403 Forbidden): Missing grant");

        let seal_err = HarborError::seal("Encryption failed");
        assert_eq!(seal_err.to_string(), "Seal error: Encryption failed");

        let sui_err = HarborError::sui("RPC failure");
        assert_eq!(sui_err.to_string(), "Sui error: RPC failure");
    }
}
