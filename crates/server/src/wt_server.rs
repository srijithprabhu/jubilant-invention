use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use common::JwtManager;
use wtransport::endpoint::SessionRequest;
use wtransport::tls::Identity;
#[allow(unused_imports)]
use wtransport::{Connection, Endpoint, ServerConfig};

pub struct WtServerConfig {
    pub bind_addr: SocketAddr,
    pub identity: Identity,
}

impl WtServerConfig {
    pub fn new(bind_addr: SocketAddr, identity: Identity) -> Self {
        Self { bind_addr, identity }
    }

    /// Builds the `wtransport::ServerConfig` using the configured bind address and TLS identity.
    pub fn build_server_config(&self) -> ServerConfig {
        ServerConfig::builder()
            .with_bind_address(self.bind_addr)
            .with_identity(&self.identity)
            .build()
    }
}

/// Helper function to extract the `token` parameter from a URL path or query string.
///
/// Example inputs:
/// - `"/wt?token=eyJhbGciOiJIUzI1..."` -> `Some("eyJhbGciOiJIUzI1...")`
/// - `"/wt?user=alice&token=xyz123"` -> `Some("xyz123")`
/// - `"/wt"` -> `None`
pub fn extract_token_from_path(path: &str) -> Option<String> {
    path.split_once("?")
        .map(|(_, value)| value.split("&"))?
        .find(|value| value.starts_with("token="))
        .map(|query| query.split_once("="))?
        .map(|(_, token)| token.to_string())
}

pub struct WebTransportServer {
    config: WtServerConfig,
    jwt_manager: Arc<JwtManager>,
}

impl WebTransportServer {
    pub fn new(config: WtServerConfig, jwt_manager: Arc<JwtManager>) -> Self {
        Self { config, jwt_manager }
    }

    pub fn config(&self) -> &WtServerConfig {
        &self.config
    }

    pub fn jwt_manager(&self) -> &Arc<JwtManager> {
        &self.jwt_manager
    }

    /// Authenticates an incoming WebTransport session request.
    ///
    /// 1. Extracts the JWT token from `session_request.path()` using `extract_token_from_path`.
    /// 2. Verifies the token using `self.jwt_manager.verify_token(&token)`.
    /// 3. Returns the authenticated `peer_id` (the JWT `sub` / user ID) on success, or an error description.
    pub fn authenticate_session_request(&self, session_request: &SessionRequest) -> Result<String, String> {
        extract_token_from_path(session_request.path())
            .map(|token| self.jwt_manager.verify_token(&token))
            .unwrap()
            .map_err(|err| err.to_string())
            .map(|claims| claims.sub)
    }

    /// Handles an established WebTransport connection lifecycle for an authenticated peer.
    ///
    /// - Accepts incoming bidirectional streams (`connection.accept_bi()`) for control messages (`proto::ControlMessage`).
    /// - Receives datagrams (`connection.receive_datagram()`) for media packets.
    /// - Handles peer disconnects gracefully.
    pub async fn handle_connection(
        &self,
        connection: Connection,
        peer_id: String,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        println!("Peer connected: {peer_id}");

        loop {
            tokio::select! {
                // Branch 1: Incoming bidirectional stream (Control messages)
                bi_res = connection.accept_bi() => {
                    match bi_res {
                        Ok((mut _send_stream, mut _recv_stream)) => {
                            // Read incoming control message bytes from recv_stream
                            // In wtransport, recv_stream.read(&mut buf) or recv_stream.read_to_end(...)
                        }
                        Err(wtransport::error::ConnectionError::LocallyClosed)
                        | Err(wtransport::error::ConnectionError::ConnectionClosed(_)) => {
                            // Peer disconnected cleanly
                            break;
                        }
                        Err(e) => {
                            eprintln!("Stream error for peer {peer_id}: {e}");
                            break;
                        }
                    }
                }

                // Branch 2: Incoming Datagram (Media packets)
                dgram_res = connection.receive_datagram() => {
                    match dgram_res {
                        Ok(_datagram) => {
                            // datagram dereferences to &[u8]
                            // Later in Phase 3/4, this will route media frames across room peers
                        }
                        Err(wtransport::error::ConnectionError::LocallyClosed)
                        | Err(wtransport::error::ConnectionError::ConnectionClosed(_)) => {
                            // Peer disconnected cleanly
                            break;
                        }
                        Err(e) => {
                            eprintln!("Datagram error for peer {peer_id}: {e}");
                            break;
                        }
                    }
                }
            }
        }

        println!("Peer disconnected: {peer_id}");
        Ok(())
    }

    /// Starts the WebTransport server listener on UDP and processes incoming connection sessions.
    ///
    /// 1. Initializes `Endpoint::server(self.config.build_server_config())?`.
    /// 2. Loops on `endpoint.accept().await` to receive incoming sessions.
    /// 3. For each incoming session:
    ///    - Awaits the `session_request`.
    ///    - Validates via `self.authenticate_session_request(&session_request)`.
    ///    - If valid: accepts session with `session_request.accept().await` and spawns `handle_connection`.
    ///    - If invalid: rejects session with `session_request.forbidden().await`.
    pub async fn serve(self: Arc<Self>) -> Result<(), Box<dyn Error + Send + Sync>> {
        // 1. Build and bind the WebTransport endpoint
        let server_config = self.config.build_server_config();
        let endpoint = Endpoint::server(server_config)?;

        // 2. Loop continuously to accept incoming sessions
        loop {
            let incoming_session = endpoint.accept().await;
            // incoming_session is an incoming QUIC connection waiting for HTTP/3 CONNECT
            let session_request = match incoming_session.await {
                Ok(req) => req,
                Err(err) => {
                    // Handshake error or client disconnect before CONNECT
                    eprintln!("Failed to negotiate session request: {err}");
                    continue;
                }
            };

            // 3. Authenticate the session
            let server = Arc::clone(&self);
            match server.authenticate_session_request(&session_request) {
                Ok(peer_id) => {
                    // 4. Accept the WebTransport session
                    match session_request.accept().await {
                        Ok(connection) => {
                            // 5. Spawn background task for this peer
                            tokio::spawn(async move {
                                if let Err(e) = server.handle_connection(connection, peer_id).await {
                                    eprintln!("Connection error: {e}");
                                }
                            });
                        }
                        Err(err) => {
                            eprintln!("Failed to accept session: {err}");
                        }
                    }
                }
                Err(reason) => {
                    eprintln!("Rejecting unauthenticated session: {reason}");
                    // 6. Reject the session with 403 Forbidden
                    let _ = session_request.forbidden().await;
                }
            }
        }
    }
}
