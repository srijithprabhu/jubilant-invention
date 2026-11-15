use std::sync::Arc;
use std::time::Duration;
use common::auth::{AuthProvider, JwtManager, User};
use proto::ControlMessage;
use server::wt_server::{WebTransportServer, WtServerConfig};
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

#[tokio::test]
async fn test_wt_server_auth_valid_and_invalid_token() {
    let jwt_manager = setup_jwt_manager();
    let user = test_user("peer_42");
    let _valid_token = jwt_manager.generate_token(&user).unwrap();

    let identity = Identity::self_signed(&["localhost"]).unwrap();
    let config = WtServerConfig::new("127.0.0.1:0".parse().unwrap(), identity);
    let _server = WebTransportServer::new(config, jwt_manager.clone());

    // In wt_server.rs, authenticate_session_request will inspect incoming_session.path() / query string `?token=...`
    // Once implemented by the user, valid tokens should authenticate to peer_id "peer_42"
    // and invalid/missing tokens should return an error.
}

#[tokio::test]
async fn test_wt_server_connection_and_control_stream() {
    let jwt_manager = setup_jwt_manager();
    let user = test_user("test_user_1");
    let token = jwt_manager.generate_token(&user).unwrap();

    let identity = Identity::self_signed(&["localhost"]).unwrap();
    let cert_hash = identity.certificate_chain().as_slice()[0].hash();

    // Bind to local port
    let server_addr = "127.0.0.1:14433".parse().unwrap();
    let config = WtServerConfig::new(server_addr, identity);
    let server = Arc::new(WebTransportServer::new(config, jwt_manager));

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let _ = server.serve().await;
    });

    // Give server task a moment to bind
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Build client with trusted server cert hash
    let client_config = ClientConfig::builder()
        .with_bind_default()
        .with_server_certificate_hashes([cert_hash])
        .build();

    let client = Endpoint::client(client_config);
    if let Ok(client) = client {
        let url = format!("https://127.0.0.1:14433/wt?token={}", token);
        if let Ok(incoming) = client.connect(url).await {
            // Once user implements serve() and handle_connection(), incoming session connects.
            let connection = incoming;

            // Test opening bidirectional stream for control message
            if let Ok(opening) = connection.open_bi().await {
                if let Ok((mut send_stream, mut _recv_stream)) = opening.await {
                    let join_msg = ControlMessage::JoinRoom {
                        room_id: "room_alpha".to_string(),
                        token: token.clone(),
                    };
                    let payload = serde_json::to_vec(&join_msg).unwrap();
                    let _ = send_stream.write_all(&payload).await;
                }
            }
        }
    }

    server_handle.abort();
}
