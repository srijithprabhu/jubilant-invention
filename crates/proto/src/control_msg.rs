use crate::media_packet::MediaKind;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMessage {
    JoinRoom {
        room_id: String,
        token: String,
    },
    RoomJoined {
        peer_id: String,
        active_peers: Vec<String>,
    },
    PeerJoined {
        peer_id: String,
    },
    PeerLeft {
        peer_id: String,
    },
    PublishTrack {
        track_id: u32,
        media_kind: MediaKind,
    },
    SubscribeTrack {
        peer_id: String,
        track_id: u32,
    },
    RequestKeyframe {
        track_id: u32,
    },
}
