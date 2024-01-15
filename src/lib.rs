use dlc::secp256k1_zkp::hashes::sha256;
use dlc::secp256k1_zkp::{All, Secp256k1};
use dlc::OracleInfo;
use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
use nostr::key::SecretKey;
use nostr::Keys;
use nostr::{EventId, Kind, Timestamp};
use rand::rngs::ThreadRng;
use schnorr_fun::adaptor::{Adaptor, EncryptedSignature};
use schnorr_fun::fun::marker::{EvenY, NonZero, Normal, Public};
use schnorr_fun::fun::{KeyPair, Point};
use schnorr_fun::nonce::{GlobalRng, Synthetic};
use schnorr_fun::{adaptor::EncryptedSign, fun::Scalar, Message, Schnorr, Signature};
use sha2::Sha256;

mod utils;

#[derive(Clone)]
pub struct NoteDuel {
    keys: Keys,
    signing_keypair: KeyPair<EvenY>,
    schnorr: Schnorr<Sha256, Synthetic<Sha256, GlobalRng<ThreadRng>>>,
    secp: Secp256k1<All>,
}

impl NoteDuel {
    pub fn new(secret_key: SecretKey) -> NoteDuel {
        let keys = Keys::new(secret_key);
        let nonce_gen = Synthetic::<Sha256, GlobalRng<ThreadRng>>::default();
        let schnorr = Schnorr::<Sha256, _>::new(nonce_gen);
        let scalar = Scalar::from_bytes(secret_key.secret_bytes()).unwrap();
        let signing_keypair = schnorr.new_keypair(scalar.non_zero().unwrap());
        let secp: Secp256k1<All> = Secp256k1::gen_new();

        Self {
            keys,
            signing_keypair,
            schnorr,
            secp,
        }
    }
}

impl NoteDuel {
    fn adaptor_sign(&self, encryption_key: [u8; 33], message: EventId) -> EncryptedSignature {
        let encryption_key: Point<Normal, Public, NonZero> =
            Point::from_bytes(encryption_key).unwrap();
        let message = Message::<Public>::raw(message.as_bytes());

        self.schnorr
            .encrypted_sign(&self.signing_keypair, &encryption_key, message)
    }

    fn decrypt_signature(&self, s_value: &[u8], encrypted_sig: EncryptedSignature) -> Signature {
        let scalar: Scalar<Public> = Scalar::from_slice(s_value).unwrap().non_zero().unwrap();

        self.schnorr.decrypt_signature(scalar, encrypted_sig)
    }

    pub fn create_tweaked_signatures(
        &self,
        losing_message: &str,
        announcement: OracleAnnouncement,
        outcomes: Vec<String>,
    ) -> Vec<EncryptedSignature> {
        let time = Timestamp::from(announcement.oracle_event.event_maturity_epoch as u64);
        let event_id = EventId::new(
            &self.keys.public_key(),
            time,
            &Kind::TextNote,
            &[],
            losing_message,
        );

        let oracle_info = OracleInfo {
            public_key: announcement.oracle_public_key,
            nonces: announcement.oracle_event.oracle_nonces,
        };

        outcomes
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
                )
                .unwrap();

                self.adaptor_sign(point.serialize(), event_id)
            })
            .collect()
    }

    pub fn complete_signature(
        &self,
        encrypted_sig: EncryptedSignature,
        attestation: OracleAttestation,
    ) -> Signature {
        let (_, s_value) =
            dlc::secp_utils::schnorrsig_decompose(&attestation.signatures[0]).unwrap();

        self.decrypt_signature(s_value, encrypted_sig)
    }
}

#[cfg(test)]
mod test {
    use crate::utils::{oracle_announcement_from_hex, oracle_attestation_from_hex};
    use crate::NoteDuel;
    use nostr::{EventId, Keys, Kind, Timestamp, UnsignedEvent};

    const ANNOUNCEMENT: &str = "00fa6568a68af95dcc8eec11bb92948e09d09fcdb7fc17a0806e3d3087534e4ae9b5de2c5265035ff5e3ebffa39e664b243955a3599280487d46bc045159b3cc5c1ef2cc6453c9b672ecb7186fa59462d69bf7d12052bbe31ac570b36b68e2b3fdd822350001cd026e5319cce1525324702134fe192c0c81f5335b79e3a090f702e144e13e3465a5c700fdd806060002016101620474657374";
    const ATTESTATION: &str = "5c1ef2cc6453c9b672ecb7186fa59462d69bf7d12052bbe31ac570b36b68e2b30001cd026e5319cce1525324702134fe192c0c81f5335b79e3a090f702e144e13e348985893b864fc0e1c68a4a40b45bff0bb378e90d535c5d7ce04e1e2abc6a762800010161";

    #[test]
    fn test() {
        let nsec = Keys::generate();
        let duel = NoteDuel::new(nsec.secret_key().unwrap());

        let ann = oracle_announcement_from_hex(ANNOUNCEMENT);
        let att = oracle_attestation_from_hex(ATTESTATION);
        let losing_message = "I lost";

        let created_at = Timestamp::from(ann.oracle_event.event_maturity_epoch as u64);
        let event_id = EventId::new(
            &nsec.public_key(),
            created_at,
            &Kind::TextNote,
            &[],
            losing_message,
        );
        let unsigned = UnsignedEvent {
            id: event_id,
            pubkey: nsec.public_key(),
            created_at,
            kind: Kind::TextNote,
            tags: vec![],
            content: losing_message.to_string(),
        };

        let sigs = duel.create_tweaked_signatures(losing_message, ann, vec!["a".to_string()]);

        let complete = duel.complete_signature(sigs[0].to_owned(), att);

        let signature =
            nostr::secp256k1::schnorr::Signature::from_slice(&complete.to_bytes()).unwrap();
        assert!(unsigned.add_signature(signature).is_ok())
    }
}
