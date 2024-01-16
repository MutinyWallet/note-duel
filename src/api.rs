use crate::error::Error;
use dlc::secp256k1_zkp::hashes::hex::ToHex;
use dlc_messages::oracle_msgs::OracleAnnouncement;
use lightning::util::ser::Writeable;
use nostr::key::XOnlyPublicKey;
use nostr::{EventId, UnsignedEvent};
use reqwest::{Client, StatusCode};
use schnorr_fun::adaptor::EncryptedSignature;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;

#[derive(Clone)]
pub struct ApiClient {
    client: Client,
    base_url: String,
}
impl ApiClient {
    pub fn new(base_url: String) -> Self {
        let client = Client::new();
        Self { client, base_url }
    }

    pub async fn create_bet(
        &self,
        oracle_announcement: OracleAnnouncement,
        oracle_event_id: EventId,
        unsigned_event: UnsignedEvent,
        counterparty_unsigned_event: UnsignedEvent,
        sigs: HashMap<String, EncryptedSignature>,
    ) -> Result<i32, Error> {
        let oracle_announcement = oracle_announcement.encode().to_hex();
        let sigs: HashMap<String, String> = sigs
            .into_iter()
            .map(|(k, v)| (k, bincode::serialize(&v).unwrap().to_hex()))
            .collect();

        let request = json!({
            "oracle_announcement": oracle_announcement,
            "oracle_event_id": oracle_event_id,
            "unsigned_event": unsigned_event,
            "counterparty_unsigned_event": counterparty_unsigned_event,
            "sigs": sigs,
        });

        let request = self
            .client
            .post(format!("{}/create-bet", &self.base_url))
            .json(&request)
            .build()?;
        let response = self.client.execute(request).await?;

        if response.status() == StatusCode::from_u16(200).unwrap() {
            let id: i32 = response.json().await?;
            Ok(id)
        } else {
            Err(Error::Api)
        }
    }

    pub async fn add_sigs(
        &self,
        id: i32,
        sigs: HashMap<String, EncryptedSignature>,
    ) -> Result<(), Error> {
        let sigs: HashMap<String, String> = sigs
            .into_iter()
            .map(|(k, v)| (k, bincode::serialize(&v).unwrap().to_hex()))
            .collect();

        let request = json!({
            "id": id,
            "sigs": sigs,
        });

        let request = self
            .client
            .post(format!("{}/add-sigs", &self.base_url))
            .json(&request)
            .build()?;
        let response = self.client.execute(request).await?;

        if response.status() == StatusCode::from_u16(200).unwrap() {
            Ok(())
        } else {
            Err(Error::Api)
        }
    }

    pub async fn list_pending_bets(&self, npub: XOnlyPublicKey) -> Result<Vec<PendingBet>, Error> {
        let request = self
            .client
            .get(format!(
                "{}/list-pending?pubkey={}",
                &self.base_url,
                npub.to_hex()
            ))
            .build()?;
        let response = self.client.execute(request).await?;

        if response.status() == StatusCode::from_u16(200).unwrap() {
            let bets: Vec<PendingBet> = response.json().await?;
            Ok(bets)
        } else {
            Err(Error::Api)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingBet {
    pub id: i32,
    pub unsigned_a: UnsignedEvent,
    pub unsigned_b: UnsignedEvent,
    pub oracle_announcement: String,
    pub needed_outcomes: Vec<String>,
}
