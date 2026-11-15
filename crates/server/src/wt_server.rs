use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use common::JwtManager;
use wtransport::endpoint::IncomingSession;
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

    /// Authenticates incoming session request by extracting the JWT token from URL query string.
    /// Expected format: `?token=<JWT>` or path `/wt?token=<JWT>`
    /// Returns the authenticated peer_id (user ID) on success, or an error message.
    pub fn authenticate_session_request(&self, incoming_session: &IncomingSession) -> Result<String, String> {
        let _ = incoming_session;
        todo!("Implement session authentication from incoming session (e.g. query param 'token')")
    }

    /// Handles an established WebTransport connection lifecycle.
    /// Multiplexes bidirectional streams for control messages and datagrams for media.
    pub async fn handle_connection(&self, connection: Connection, peer_id: String) -> Result<(), Box<dyn Error + Send + Sync>> {
        let _ = (connection, peer_id);
        todo!("Implement connection stream and datagram handling loop")
    }

    /// Starts the WebTransport server listener on UDP and accepts incoming sessions.
    pub async fn serve(self: Arc<Self>) -> Result<(), Box<dyn Error + Send + Sync>> {
        todo!("Implement WebTransport server accept loop")
    }
}
