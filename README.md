# harbor-rs

Rust SDK for Harbor.

This crate provides:

- `harbor-core` for interacting with the Harbor API, including bucket management, file uploads, and retrieving storage statuses.
- `harbor-demo` demonstrating a full end-to-end round trip (Reserve -> Sign -> Finalize -> Seal Encrypt -> Upload -> Download -> Seal Decrypt -> Verify & Delete).

## Quickstart

Use the `harbor_core::client::HarborClient` to interact with Harbor's API. You will need an API Key and a base URL.

```rust
use std::time::Duration;
use harbor_core::client::{HarborClient, HarborClientOptions};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let options = HarborClientOptions {
        api_key: "your_harbor_api_key".to_string(),
        base_url: "https://api.testnet.harbor.io".to_string(),
        upload_retry_delay: Duration::from_millis(500),
        upload_max_retries: 5,
        poll_delay: Duration::from_secs(1),
        poll_max_attempts: 120,
    };
    
    let client = HarborClient::new(options);
    
    // List available spaces
    let spaces = client.list_spaces().await?;
    if let Some(space) = spaces.first() {
        println!("Space ID: {}", space.id);
        
        // Reserve a new private bucket
        let reservation = client.reserve_bucket(&space.id, "my_test_bucket").await?;
        println!("Reserved Bucket ID: {}", reservation.data.id);
    }
    
    Ok(())
}
```

## Run the Demo

The demo app maps environment variables to run a complete end-to-end flow. The flow involves reserving a bucket on Harbor, finalizing it by signing the payload, encrypting a file locally using Seal, uploading the file to Harbor, polling for completion, downloading the file back, and decrypting it with Seal to verify the contents.

Required Environment Variables:

```sh
# Your Harbor API Key
export HARBOR_API_KEY="hbr_..."

# Your Sui Private Key used to sign the reservation
export HARBOR_SERVICE_PRIVKEY="suiprivkey..."
```

Run the demo:

```sh
cargo run -p harbor-demo --bin harbor-demo
```

## APIs

### Harbor Client

The `HarborClient` directly exposes lower-level actions against the Harbor REST API endpoints. Common methods include:

- `list_spaces()` fetches the spaces associated with the authenticated API key.
- `reserve_bucket(space_id, name)` initializes a new private bucket allocation.
- `finalize_bucket(bucket_id, signature)` claims the reserved bucket on-chain using a verified signature.
- `upload_file(bucket_id, file_name, ciphertext, on_retry_callback)` uploads encrypted binary data to Walrus via Harbor.
- `poll_until_completed(bucket_id, file_id, on_tick_callback)` polls the Harbor API until a file is completely propagated.
- `download_file(bucket_id, file_id)` retrieves the raw bytes of an uploaded file.
- `delete_file(bucket_id, file_id)` and `delete_bucket(bucket_id)` provide cleanup operations.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
