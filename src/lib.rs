use crate::api::{ApiClient, UserBet};
use crate::utils::oracle_announcement_from_str;
use dlc::secp256k1_zkp::hashes::sha256;
use dlc::secp256k1_zkp::{All, Secp256k1};
use dlc::OracleInfo;
use dlc_messages::oracle_msgs::{EventDescriptor, OracleAnnouncement, OracleAttestation};
use error::Error;
use gloo_utils::format::JsValueSerdeExt;
use lightning::util::ser::Readable;
use nostr::key::SecretKey;
use nostr::key::{FromSkStr, XOnlyPublicKey};
use nostr::{Event, EventId, Filter, FromBech32, Kind, Timestamp, ToBech32};
use nostr::{Keys, UnsignedEvent};
use nostr_sdk::Client;
use rand::rngs::ThreadRng;
use schnorr_fun::adaptor::{Adaptor, EncryptedSignature};
use schnorr_fun::fun::marker::{EvenY, NonZero, Normal, Public};
use schnorr_fun::fun::{KeyPair, Point};
use schnorr_fun::nonce::{GlobalRng, Synthetic};
use schnorr_fun::{adaptor::EncryptedSign, fun::Scalar, Message, Schnorr, Signature};
use sha2::Sha256;
use std::collections::HashMap;
use std::time::Duration;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

mod api;
mod error;
pub mod models;
mod utils;

const RELAYS: [&str; 10] = [
    "wss://nostr.mutinywallet.com",
    "wss://relay.snort.social",
    "wss://nos.lol",
    "wss://nostr.fmt.wiz.biz",
    "wss://relay.damus.io",
    "wss://relay.primal.net",
    "wss://nostr.wine",
    "wss://relay.nostr.band",
    "wss://nostr.zbd.gg",
    "wss://relay.nos.social",
];

#[derive(Clone)]
#[wasm_bindgen]
pub struct NoteDuel {
    keys: Keys,
    signing_keypair: KeyPair<EvenY>,
    schnorr: Schnorr<Sha256, Synthetic<Sha256, GlobalRng<ThreadRng>>>,
    client: Client,
    api: ApiClient,
    secp: Secp256k1<All>,
}

impl NoteDuel {
    pub async fn new(secret_key: SecretKey, base_url: String) -> Result<NoteDuel, Error> {
        let keys = Keys::new(secret_key);
        let nonce_gen = Synthetic::<Sha256, GlobalRng<ThreadRng>>::default();
        let schnorr = Schnorr::<Sha256, _>::new(nonce_gen);
        let scalar =
            Scalar::from_bytes(secret_key.secret_bytes()).ok_or(Error::InvalidArguments)?;
        let scalar = scalar.non_zero().ok_or(Error::InvalidArguments)?;
        let signing_keypair = schnorr.new_keypair(scalar);
        let secp: Secp256k1<All> = Secp256k1::gen_new();

        let api = ApiClient::new(base_url);

        let client = Client::new(&keys);
        client.add_relays(RELAYS).await?;
        client.connect().await;

        Ok(Self {
            keys,
            signing_keypair,
            schnorr,
            client,
            api,
            secp,
        })
    }

    fn adaptor_sign(&self, encryption_key: [u8; 33], message: EventId) -> EncryptedSignature {
        let encryption_key: Point<Normal, Public, NonZero> =
            Point::from_bytes(encryption_key).expect("Valid pubkey");
        let message = Message::<Public>::raw(message.as_bytes());

        self.schnorr
            .encrypted_sign(&self.signing_keypair, &encryption_key, message)
    }

    fn decrypt_signature(
        &self,
        s_value: &[u8],
        encrypted_sig: EncryptedSignature,
    ) -> Result<Signature, Error> {
        let scalar: Scalar<Public> = Scalar::from_slice(s_value)
            .ok_or(Error::InvalidArguments)?
            .non_zero()
            .ok_or(Error::InvalidArguments)?;

        Ok(self.schnorr.decrypt_signature(scalar, encrypted_sig))
    }

    /// Creates the unsigned nostr event
    pub fn create_unsigned_event(
        &self,
        losing_message: &str,
        ann: &OracleAnnouncement,
        pubkey: Option<XOnlyPublicKey>,
    ) -> UnsignedEvent {
        let pubkey = pubkey.unwrap_or(self.keys.public_key());
        let created_at = Timestamp::from(ann.oracle_event.event_maturity_epoch as u64);
        let event_id = EventId::new(&pubkey, created_at, &Kind::TextNote, &[], losing_message);
        UnsignedEvent {
            id: event_id,
            pubkey,
            created_at,
            kind: Kind::TextNote,
            tags: vec![],
            content: losing_message.to_string(),
        }
    }

    /// Creates signatures that are encrypted
    pub async fn create_bet(
        &self,
        winning_message: &str,
        losing_message: &str,
        announcement: OracleAnnouncement,
        announcement_id: EventId,
        counter_party: XOnlyPublicKey,
        outcomes: Vec<String>,
    ) -> Result<i32, Error> {
        let winning_unsigned_event =
            self.create_unsigned_event(winning_message, &announcement, None);
        let winning_counter_party_unsigned_event =
            self.create_unsigned_event(winning_message, &announcement, Some(counter_party));

        let losing_unsigned_event = self.create_unsigned_event(losing_message, &announcement, None);
        let losing_counter_party_unsigned_event =
            self.create_unsigned_event(losing_message, &announcement, Some(counter_party));

        let oracle_info = OracleInfo {
            public_key: announcement.oracle_public_key,
            nonces: announcement.oracle_event.oracle_nonces.clone(),
        };

        let all_outcomes = if let EventDescriptor::EnumEvent(ref desc) =
            announcement.oracle_event.event_descriptor
        {
            if !outcomes.iter().all(|o| desc.outcomes.contains(o)) {
                return Err(Error::InvalidArguments);
            }
            desc.outcomes.clone()
        } else {
            return Err(Error::InvalidArguments);
        };

        if all_outcomes.len() == outcomes.len() {
            return Err(Error::InvalidArguments);
        }

        let sigs: HashMap<String, EncryptedSignature> = all_outcomes
            .into_iter()
            .map(|outcome| {
                let message = vec![
                    dlc::secp256k1_zkp::Message::from_hashed_data::<sha256::Hash>(
                        outcome.as_bytes(),
                    ),
                ];
                let point = dlc::get_adaptor_point_from_oracle_info(
                    &self.secp,
                    &[oracle_info.clone()],
                    &[message],
                )?;

                let id = if outcomes.contains(&outcome) {
                    winning_unsigned_event.id
                } else {
                    losing_unsigned_event.id
                };

                let sig = self.adaptor_sign(point.serialize(), id);

                Ok((outcome, sig))
            })
            .collect::<Result<_, Error>>()?;

        let id = self
            .api
            .create_bet(
                announcement,
                announcement_id,
                winning_unsigned_event,
                losing_unsigned_event,
                winning_counter_party_unsigned_event,
                losing_counter_party_unsigned_event,
                sigs,
            )
            .await?;

        Ok(id)
    }

    pub async fn accept_bet(&self, id: i32) -> Result<(), Error> {
        let events = self.list_pending_events().await?;
        let event: UserBet = events
            .into_iter()
            .find(|e| e.id == id)
            .ok_or(Error::PendingEventNotFound)?;

        let ann = oracle_announcement_from_str(&event.oracle_announcement)?;

        let oracle_info = OracleInfo {
            public_key: ann.oracle_public_key,
            nonces: ann.oracle_event.oracle_nonces,
        };

        let mut sigs: HashMap<String, EncryptedSignature> =
            HashMap::with_capacity(event.user_outcomes.len() + event.counterparty_outcomes.len());

        for outcome in event.user_outcomes {
            let message = vec![
                dlc::secp256k1_zkp::Message::from_hashed_data::<sha256::Hash>(outcome.as_bytes()),
            ];
            let point = dlc::get_adaptor_point_from_oracle_info(
                &self.secp,
                &[oracle_info.clone()],
                &[message],
            )?;

            let sig = self.adaptor_sign(point.serialize(), event.win_b.id);

            sigs.insert(outcome, sig);
        }

        for outcome in event.counterparty_outcomes {
            let message = vec![
                dlc::secp256k1_zkp::Message::from_hashed_data::<sha256::Hash>(outcome.as_bytes()),
            ];
            let point = dlc::get_adaptor_point_from_oracle_info(
                &self.secp,
                &[oracle_info.clone()],
                &[message],
            )?;

            let sig = self.adaptor_sign(point.serialize(), event.lose_b.id);

            sigs.insert(outcome, sig);
        }

        self.api.add_sigs(id, sigs).await?;

        Ok(())
    }

    /// Completes the signatures to becomes a valid signature
    pub fn complete_signature(
        &self,
        encrypted_sig: EncryptedSignature,
        attestation: OracleAttestation,
    ) -> Result<Signature, Error> {
        let (_, s_value) = dlc::secp_utils::schnorrsig_decompose(&attestation.signatures[0])?;

        self.decrypt_signature(s_value, encrypted_sig)
    }

    /// Returns DLC oracle announcements
    pub async fn get_oracle_events(&self) -> Result<Vec<OracleAnnouncement>, Error> {
        let filter = Filter::new().kind(Kind::Custom(88)).limit(20);

        let events = self
            .client
            .get_events_of(vec![filter], Some(Duration::from_secs(3)))
            .await?;

        Ok(events
            .into_iter()
            .filter_map(decode_announcement_event)
            .collect())
    }

    pub async fn list_pending_events(&self) -> Result<Vec<UserBet>, Error> {
        self.api.list_pending_bets(self.keys.public_key()).await
    }

    pub async fn list_events(&self) -> Result<Vec<UserBet>, Error> {
        self.api.list_bets(self.keys.public_key()).await
    }
}

fn decode_announcement_event(event: Event) -> Option<OracleAnnouncement> {
    if event.kind.as_u64() == 88 {
        let bytes = base64::decode(event.content).ok()?;
        let mut cursor = std::io::Cursor::new(&bytes);
        OracleAnnouncement::read(&mut cursor).ok()
    } else {
        None
    }
}

#[wasm_bindgen]
impl NoteDuel {
    #[wasm_bindgen(constructor)]
    pub async fn new_wasm(nsec: String, base_url: String) -> Result<NoteDuel, Error> {
        utils::set_panic_hook();
        let keys = Keys::from_sk_str(&nsec)?;
        Self::new(keys.secret_key().expect("just created"), base_url).await
    }

    /// Get current pubkey
    pub fn get_npub(&self) -> String {
        self.keys.public_key().to_bech32().expect("bech32")
    }

    /// Creates signatures that are encrypted
    pub async fn create_bet_wasm(
        &self,
        winning_message: String,
        losing_message: String,
        announcement: String,
        announcement_id: String,
        counter_party: String,
        outcomes: Vec<String>,
    ) -> Result<(), Error> {
        let announcement = oracle_announcement_from_str(&announcement)?;
        let announcement_id = EventId::from_hex(&announcement_id)?;
        let counter_party = XOnlyPublicKey::from_bech32(counter_party)?;
        self.create_bet(
            &winning_message,
            &losing_message,
            announcement,
            announcement_id,
            counter_party,
            outcomes,
        )
        .await?;

        Ok(())
    }

    pub async fn accept_bet_wasm(&self, id: i32) -> Result<(), Error> {
        self.accept_bet(id).await?;

        Ok(())
    }

    /// Returns DLC oracle announcements
    pub async fn get_oracle_events_wasm(
        &self,
    ) -> Result<JsValue /* Vec<models::Announcement> */, Error> {
        let vec = self.get_oracle_events().await?;
        let vec: Vec<models::Announcement> = vec.into_iter().map(|i| i.into()).collect();
        Ok(JsValue::from_serde(&vec)?)
    }

    pub async fn list_pending_events_wasm(&self) -> Result<JsValue /* Vec<UserBet> */, Error> {
        let res = self.list_pending_events().await?;
        Ok(JsValue::from_serde(&res)?)
    }

    pub async fn list_events_wasm(&self) -> Result<JsValue /* Vec<UserBet> */, Error> {
        let res = self.list_events().await?;
        Ok(JsValue::from_serde(&res)?)
    }

    /// Decodes an oracle announcements
    pub fn decode_announcement(str: String) -> Result<models::Announcement, Error> {
        let ann = oracle_announcement_from_str(&str)?;
        Ok(ann.into())
    }
}

#[cfg(test)]
mod test {
    use crate::utils::{oracle_announcement_from_str, sleep};
    use crate::NoteDuel;
    use dlc::secp256k1_zkp::hashes::hex::ToHex;
    use dlc_messages::oracle_msgs::EventDescriptor;
    use nostr::{EventId, Keys};
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    const ANNOUNCEMENT: &str = "ypyyyX6pdZUM+OovHftxK9StImd8F7nxmr/eTeyR/5koOVVe/EaNw1MAeJm8LKDV1w74Fr+UJ+83bVP3ynNmjwKbtJr9eP5ie2Exmeod7kw4uNsuXcw6tqJF1FXH3fTF/dgiOwAByEOAEd95715DKrSLVdN/7cGtOlSRTQ0/LsW/p3BiVOdlpccA/dgGDAACBDEyMzQENDU2NwR0ZXN0";
    const BASE_URL: &str = "https://api.noteduel.com";

    #[test]
    async fn test_full_flow() {
        let nsec_a = Keys::generate();
        let nsec_b = Keys::generate();
        let duel_a = NoteDuel::new(nsec_a.secret_key().unwrap(), BASE_URL.to_string())
            .await
            .unwrap();
        let duel_b = NoteDuel::new(nsec_b.secret_key().unwrap(), BASE_URL.to_string())
            .await
            .unwrap();

        let ann = oracle_announcement_from_str(ANNOUNCEMENT).unwrap();
        let winning_message = "I win";
        let losing_message = "I lost";

        let outcomes = match ann.oracle_event.event_descriptor {
            EventDescriptor::EnumEvent(ref e) => e.outcomes.clone(),
            EventDescriptor::DigitDecompositionEvent(_) => unreachable!(),
        };

        let id = duel_a
            .create_bet(
                winning_message,
                losing_message,
                ann,
                EventId::from_hex(
                    "d30e6c857a900ebefbf7dc3b678ead9215f4345476067e146ded973971286529",
                )
                .unwrap(),
                nsec_b.public_key(),
                vec![outcomes[0].clone()],
            )
            .await
            .unwrap();

        let mut found = false;
        for _ in 0..5 {
            let items = duel_b.list_pending_events().await.unwrap_or_default();
            if items.is_empty() {
                assert!(!items[0].counterparty_outcomes.is_empty());
                assert!(!items[0].user_outcomes.is_empty());

                sleep(250).await
            } else {
                found = true;
                break;
            }
        }
        if !found {
            panic!(
                "Never got pending event {id} {} {}",
                nsec_a.public_key().to_hex(),
                nsec_b.public_key().to_hex()
            );
        }

        duel_b.accept_bet(id).await.unwrap();

        let events_a = duel_a.list_events().await.unwrap();
        let events_b = duel_b.list_events().await.unwrap();

        assert_eq!(events_a.len(), 1);
        assert_eq!(events_b.len(), 1);

        sleep(5_000).await;

        let events_a = duel_a.list_events().await.unwrap();
        let ev = &events_a[0];

        assert!(ev.win_outcome_event_id.is_some());
        assert!(ev.lose_outcome_event_id.is_some());
    }
}
