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

    #[allow(clippy::too_many_arguments)]
    pub async fn create_bet(
        &self,
        oracle_announcement: OracleAnnouncement,
        oracle_event_id: EventId,
        win_event: UnsignedEvent,
        lose_event: UnsignedEvent,
        counterparty_win_event: UnsignedEvent,
        counterparty_lose_event: UnsignedEvent,
        sigs: HashMap<String, EncryptedSignature>,
    ) -> Result<i32, Error> {
        let oracle_announcement = oracle_announcement.encode().to_hex();

        let request = json!({
            "oracle_announcement": oracle_announcement,
            "oracle_event_id": oracle_event_id,
            "win_event": win_event,
            "lose_event": lose_event,
            "counterparty_win_event": counterparty_win_event,
            "counterparty_lose_event": counterparty_lose_event,
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

    pub async fn list_pending_bets(&self, npub: XOnlyPublicKey) -> Result<Vec<UserBet>, Error> {
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
            let bets: Vec<UserBet> = response.json().await?;
            Ok(bets)
        } else {
            Err(Error::Api)
        }
    }

    pub async fn list_bets(&self, npub: XOnlyPublicKey) -> Result<Vec<UserBet>, Error> {
        let request = self
            .client
            .get(format!(
                "{}/list-bets?pubkey={}",
                &self.base_url,
                npub.to_hex()
            ))
            .build()?;
        let response = self.client.execute(request).await?;

        if response.status() == StatusCode::from_u16(200).unwrap() {
            let bets: Vec<UserBet> = response.json().await?;
            Ok(bets)
        } else {
            Err(Error::Api)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserBet {
    pub id: i32,
    pub win_a: UnsignedEvent,
    pub lose_a: UnsignedEvent,
    pub win_b: UnsignedEvent,
    pub lose_b: UnsignedEvent,
    pub oracle_announcement: String,
    pub oracle_event_id: EventId,
    pub user_outcomes: Vec<String>,
    pub counterparty_outcomes: Vec<String>,
    pub win_outcome_event_id: Option<EventId>,
    pub lose_outcome_event_id: Option<EventId>,
}
