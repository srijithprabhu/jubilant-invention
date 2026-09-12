use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MediaKind {
    AudioOpus = 1,
    VideoVp8 = 2,
    VideoAv1 = 3,
    VideoH264 = 4,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaPacketHeader {
    pub magic: u16,           // Protocol magic identifier (0x5643 'VC')
    pub track_id: u32,        // Unique track identifier
    pub sequence_number: u32, // Monotonically increasing sequence
    pub timestamp: u64,       // Presentation timestamp (microseconds)
    pub media_kind: MediaKind,// Codec / media type
    pub is_keyframe: bool,    // Video keyframe flag
    pub chunk_index: u16,     // Chunk index for fragmented frames
    pub chunk_total: u16,     // Total chunks for this frame
    pub payload_len: u16,     // Length of media payload bytes
}

pub const PROTOCOL_MAGIC: u16 = 0x5643;
