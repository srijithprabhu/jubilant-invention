use std::sync::Arc;
use std::time::Duration;
use common::auth::{AuthProvider, JwtManager, User};
use proto::{ControlMessage, MediaKind, MediaPacketHeader, PROTOCOL_MAGIC};
use server::wt_server::{extract_token_from_path, WebTransportServer, WtServerConfig};
use wtransport::tls::Identity;
use wtransport::{ClientConfig, Endpoint};

fn setup_jwt_manager() -> Arc<JwtManager> {
    Arc::new(JwtManager::new(b"test-secret-key-32-bytes-long!!", 3600))
}

fn test_user(id: &str) -> User {
    User {
        id: id.to_string(),
        email: format!("{}@example.com", id),
        name: format!("User {}", id),
        avatar_url: None,
        provider: AuthProvider::Google,
        provider_user_id: format!("google_{}", id),
    }
}

#[test]
fn test_extract_token_from_path() {
    assert_eq!(
        extract_token_from_path("/wt?token=jwt_sample_token"),
        Some("jwt_sample_token".to_string())
    );
    assert_eq!(
        extract_token_from_path("/wt?room=lobby&token=jwt_sample_2"),
        Some("jwt_sample_2".to_string())
    );
    assert_eq!(
        extract_token_from_path("/wt?token=jwt_sample_3&extra=123"),
        Some("jwt_sample_3".to_string())
    );
    assert_eq!(
        extract_token_from_path("?token=standalone_token"),
        Some("standalone_token".to_string())
    );
    assert_eq!(extract_token_from_path("/wt?other=123"), None);
    assert_eq!(extract_token_from_path("/wt"), None);
    assert_eq!(extract_token_from_path(""), None);
}

#[tokio::test]
async fn test_wt_server_auth_valid_and_invalid_token() {
    let jwt_manager = setup_jwt_manager();
    let user = test_user("peer_42");
    let valid_token = jwt_manager.generate_token(&user).unwrap();

    let identity = Identity::self_signed(&["localhost"]).unwrap();
    let cert_hash = identity.certificate_chain().as_slice()[0].hash();

    let server_addr = "127.0.0.1:14435".parse().unwrap();
    let config = WtServerConfig::new(server_addr, identity);
    let server = Arc::new(WebTransportServer::new(config, jwt_manager));

    let server_handle = tokio::spawn(async move {
        let _ = server.serve().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_config = ClientConfig::builder()
        .with_bind_default()
        .with_server_certificate_hashes([cert_hash])
        .build();

    let client = Endpoint::client(client_config).expect("Client endpoint build failed");

    // 1. Connect with valid token -> should succeed
    let valid_url = format!("https://127.0.0.1:14435/wt?token={}", valid_token);
    let valid_connect_res = client.connect(valid_url).await;
    assert!(
        valid_connect_res.is_ok(),
        "Client with valid JWT token should successfully connect to server"
    );

    // 2. Connect with invalid token -> should fail
    let invalid_url = "https://127.0.0.1:14435/wt?token=invalid.jwt.token";
    let invalid_connect_res = client.connect(invalid_url).await;
    assert!(
        invalid_connect_res.is_err(),
        "Client with invalid JWT token should be rejected"
    );

    // 3. Connect with missing token -> should fail
    let missing_url = "https://127.0.0.1:14435/wt";
    let missing_connect_res = client.connect(missing_url).await;
    assert!(
        missing_connect_res.is_err(),
        "Client without token should be rejected"
    );

    server_handle.abort();
}

#[tokio::test]
async fn test_wt_server_connection_and_control_stream() {
    let jwt_manager = setup_jwt_manager();
    let user = test_user("test_user_1");
    let token = jwt_manager.generate_token(&user).unwrap();

    let identity = Identity::self_signed(&["localhost"]).unwrap();
    let cert_hash = identity.certificate_chain().as_slice()[0].hash();

    let server_addr = "127.0.0.1:14436".parse().unwrap();
    let config = WtServerConfig::new(server_addr, identity);
    let server = Arc::new(WebTransportServer::new(config, jwt_manager));

    let server_handle = tokio::spawn(async move {
        let _ = server.serve().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_config = ClientConfig::builder()
        .with_bind_default()
        .with_server_certificate_hashes([cert_hash])
        .build();

    let client = Endpoint::client(client_config).expect("Client endpoint build failed");
    let url = format!("https://127.0.0.1:14436/wt?token={}", token);
    let connection = client.connect(url).await.expect("Failed to connect");

    // Open bidirectional stream for control message
    let opening = connection.open_bi().await.expect("Failed to initiate bi stream");
    let (mut send_stream, mut _recv_stream) = opening.await.expect("Failed to establish bi stream");

    let join_msg = ControlMessage::JoinRoom {
        room_id: "room_alpha".to_string(),
        token: token.clone(),
    };
    let payload = serde_json::to_vec(&join_msg).unwrap();
    send_stream.write_all(&payload).await.expect("Failed to send control message");

    server_handle.abort();
}

#[tokio::test]
async fn test_wt_server_media_datagram() {
    let jwt_manager = setup_jwt_manager();
    let user = test_user("datagram_user");
    let token = jwt_manager.generate_token(&user).unwrap();

    let identity = Identity::self_signed(&["localhost"]).unwrap();
    let cert_hash = identity.certificate_chain().as_slice()[0].hash();

    let server_addr = "127.0.0.1:14437".parse().unwrap();
    let config = WtServerConfig::new(server_addr, identity);
    let server = Arc::new(WebTransportServer::new(config, jwt_manager));

    let server_handle = tokio::spawn(async move {
        let _ = server.serve().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_config = ClientConfig::builder()
        .with_bind_default()
        .with_server_certificate_hashes([cert_hash])
        .build();

    let client = Endpoint::client(client_config).expect("Client endpoint build failed");
    let url = format!("https://127.0.0.1:14437/wt?token={}", token);
    let connection = client.connect(url).await.expect("Failed to connect");

    // Send a media packet header datagram
    let header = MediaPacketHeader {
        magic: PROTOCOL_MAGIC,
        track_id: 1,
        sequence_number: 1,
        timestamp: 1000,
        media_kind: MediaKind::VideoVp8,
        is_keyframe: true,
        chunk_index: 0,
        chunk_total: 1,
        payload_len: 4,
    };
    let dgram_bytes = serde_json::to_vec(&header).unwrap();
    connection.send_datagram(&dgram_bytes).expect("Failed to send datagram");

    server_handle.abort();
}
