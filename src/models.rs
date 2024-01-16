use crate::api::UserBet;
use dlc::secp256k1_zkp::hashes::hex::ToHex;
use dlc_messages::oracle_msgs::{EventDescriptor, OracleAnnouncement, OracleAttestation};
use gloo_utils::format::JsValueSerdeExt;
use nostr::{EventId, UnsignedEvent};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Announcement {
    announcement_signature: String,
    oracle_public_key: String,
    oracle_nonces: Vec<String>,
    pub event_maturity_epoch: u32,
    outcomes: Vec<String>,
    event_id: String,
}

#[wasm_bindgen]
impl Announcement {
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> JsValue {
        JsValue::from_serde(&serde_json::to_value(self).unwrap()).unwrap()
    }

    #[wasm_bindgen(getter)]
    pub fn announcement_signature(&self) -> String {
        self.announcement_signature.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn oracle_public_key(&self) -> String {
        self.oracle_public_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn oracle_nonces(&self) -> Vec<String> {
        self.oracle_nonces.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn outcomes(&self) -> Vec<String> {
        self.outcomes.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn event_id(&self) -> String {
        self.event_id.clone()
    }
}

impl From<OracleAnnouncement> for Announcement {
    fn from(value: OracleAnnouncement) -> Self {
        let outcomes = match value.oracle_event.event_descriptor {
            EventDescriptor::EnumEvent(e) => e.outcomes,
            EventDescriptor::DigitDecompositionEvent(_) => {
                unimplemented!("Numeric events not supported")
            }
        };

        Self {
            announcement_signature: value.announcement_signature.to_hex(),
            oracle_public_key: value.announcement_signature.to_hex(),
            oracle_nonces: value
                .oracle_event
                .oracle_nonces
                .iter()
                .map(|x| x.to_hex())
                .collect(),
            event_maturity_epoch: value.oracle_event.event_maturity_epoch,
            outcomes,
            event_id: value.oracle_event.event_id,
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    oracle_public_key: String,
    outcomes: Vec<String>,
    signatures: Vec<String>,
}

#[wasm_bindgen]
impl Attestation {
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> JsValue {
        JsValue::from_serde(&serde_json::to_value(self).unwrap()).unwrap()
    }

    #[wasm_bindgen(getter)]
    pub fn oracle_public_key(&self) -> String {
        self.oracle_public_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn outcomes(&self) -> Vec<String> {
        self.outcomes.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn signatures(&self) -> Vec<String> {
        self.signatures.clone()
    }
}

impl From<OracleAttestation> for Attestation {
    fn from(value: OracleAttestation) -> Self {
        Self {
            oracle_public_key: value.oracle_public_key.to_hex(),
            signatures: value.signatures.iter().map(|x| x.to_hex()).collect(),
            outcomes: value.outcomes,
        }
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bet {
    pub id: i32,
    unsigned_a: UnsignedEvent,
    unsigned_b: UnsignedEvent,
    oracle_announcement: String,
    oracle_event_id: EventId,
    user_outcomes: Vec<String>,
    counterparty_outcomes: Vec<String>,
    outcome_event_id: Option<EventId>,
}

#[wasm_bindgen]
impl Bet {
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> JsValue {
        JsValue::from_serde(&serde_json::to_value(self).unwrap()).unwrap()
    }
}

impl From<UserBet> for Bet {
    fn from(value: UserBet) -> Self {
        Bet {
            id: value.id,
            unsigned_a: value.unsigned_a,
            unsigned_b: value.unsigned_b,
            oracle_announcement: value.oracle_announcement,
            oracle_event_id: value.oracle_event_id,
            user_outcomes: value.user_outcomes,
            counterparty_outcomes: value.counterparty_outcomes,
            outcome_event_id: value.outcome_event_id,
        }
    }
}
