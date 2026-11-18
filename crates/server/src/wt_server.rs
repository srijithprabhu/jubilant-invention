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
    let _ = path;
    todo!("Extract the 'token' query parameter value from the given URL path")
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
        let _ = session_request;
        todo!("Implement session authentication from session_request path and verify JWT token")
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
        let _ = (connection, peer_id);
        todo!("Implement connection stream and datagram handling loop for the peer")
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
        todo!("Implement WebTransport server accept loop")
    }
}
