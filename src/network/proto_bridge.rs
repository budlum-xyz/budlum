use crate::consensus::pos::SlashingEvidence;
use crate::network::protocol::NetworkMessage;
use crate::{Block, BlockHeader, Transaction};

#[allow(clippy::all)]
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/budlum.network.rs"));
}
