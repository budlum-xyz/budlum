//! A Garden network in memory for the unit tests of this module tree.
//!
//! It drives the real state machine: every block is built, signed and voted
//! the way a validator does it, without a network in between.

use super::state::GardenLedger;
use super::types::{
    invite_keypair, join_message, GardenBlock, GardenCommit, GardenContentKind, GardenFounding,
    GardenGenesis, GardenKey, GardenLimits, GardenTx, GardenTxKind, GardenVote, SignedGardenTx,
};
use crate::crypto::primitives::KeyPair;
use crate::domain::types::Hash32;
use std::collections::BTreeMap;

pub(crate) const TOKEN: Hash32 = [5u8; 32];

pub(crate) struct Net {
    pub(crate) ledger: GardenLedger,
    pub(crate) keys: BTreeMap<GardenKey, KeyPair>,
    pub(crate) host: GardenKey,
    pub(crate) clock: u64,
}

impl Net {
    pub(crate) fn new() -> Self {
        let host = KeyPair::generate().unwrap();
        let genesis = GardenGenesis::new(
            GardenFounding {
                title: "Room".into(),
                host_name: "host".into(),
                host_address: String::new(),
                limits: GardenLimits::default(),
            },
            host.public_key_bytes(),
            1_000,
            1,
            &TOKEN,
        )
        .unwrap();
        let host_key = host.public_key_bytes();
        let mut keys = BTreeMap::new();
        keys.insert(host_key, host);
        Self {
            ledger: GardenLedger::new(genesis).unwrap(),
            keys,
            host: host_key,
            clock: 1_000,
        }
    }

    pub(crate) fn key(&self, key: &GardenKey) -> &KeyPair {
        self.keys.get(key).unwrap()
    }

    pub(crate) fn tx(&self, sender: &GardenKey, kind: GardenTxKind) -> SignedGardenTx {
        GardenTx {
            chain_id: self.ledger.state.chain_id(),
            sender: *sender,
            nonce: self.ledger.state.next_nonce(sender),
            kind,
        }
        .sign(self.key(sender))
        .unwrap()
    }

    pub(crate) fn join_tx(&mut self, name: &str) -> (GardenKey, SignedGardenTx) {
        let kp = KeyPair::generate().unwrap();
        let key = kp.public_key_bytes();
        let signature = invite_keypair(&TOKEN)
            .unwrap()
            .sign(&join_message(self.ledger.state.chain_id(), &key))
            .to_vec();
        self.keys.insert(key, kp);
        let tx = self.tx(
            &key,
            GardenTxKind::Join {
                name: name.into(),
                address: String::new(),
                invite_signature: signature,
            },
        );
        (key, tx)
    }

    pub(crate) fn block(&mut self, txs: Vec<SignedGardenTx>) -> Result<GardenBlock, String> {
        self.clock += 10;
        let state = &self.ledger.state;
        let proposer = state.leader(0).ok_or("no leader")?;
        let (header, _) = state.build_header(&txs, proposer, 0, self.clock)?;
        let proposer_signature = self.key(&proposer).sign(&header.hash()).to_vec();
        Ok(GardenBlock {
            header,
            txs,
            proposer_signature,
        })
    }

    pub(crate) fn votes(&self, block: &GardenBlock, voters: &[GardenKey]) -> Vec<GardenVote> {
        voters
            .iter()
            .map(|k| GardenVote::sign(&block.header, self.key(k)))
            .collect()
    }

    pub(crate) fn commit(&mut self, txs: Vec<SignedGardenTx>) -> Result<(), String> {
        let block = self.block(txs)?;
        let voters = self.ledger.state.electorate(&block.txs);
        let votes = self.votes(&block, &voters);
        self.ledger.append(GardenCommit { block, votes })
    }

    pub(crate) fn join(&mut self, name: &str) -> GardenKey {
        let (key, tx) = self.join_tx(name);
        self.commit(vec![tx]).unwrap();
        key
    }

    pub(crate) fn publish(&self, sender: &GardenKey, id: u8) -> SignedGardenTx {
        self.tx(
            sender,
            GardenTxKind::Publish {
                kind: GardenContentKind::Message,
                content_id: [id; 32],
                size: 5,
                mime: "text/plain".into(),
                caption: String::new(),
            },
        )
    }
}
