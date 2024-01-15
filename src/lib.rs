use std::io::Cursor;

use dlc::secp256k1_zkp::hashes::hex::{FromHex, ToHex};
use dlc::secp256k1_zkp::hashes::sha256;
use dlc::secp256k1_zkp::{All, Message, Secp256k1};
use dlc::OracleInfo;
use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
use lightning::util::ser::Readable;
use nostr::key::FromSkStr;
use nostr::{EventId, Keys, Kind, Timestamp};
use schnorr_fun::adaptor::EncryptedSignature;

use crate::sign::{adaptor_sign, decrypt_signature};

mod sign;
mod utils;

// #[wasm_bindgen]
pub fn create_tweaked_signatures(
    nsec: String,
    losing_message: String,
    announcement: String,
    outcomes: Vec<String>,
) -> Vec<String> {
    let nsec = Keys::from_sk_str(&nsec).unwrap();
    let announcement = oracle_announcement_from_hex(&announcement);
    let secp: Secp256k1<All> = Secp256k1::gen_new();

    let time = Timestamp::from(announcement.oracle_event.event_maturity_epoch as u64);
    let event_id = EventId::new(
        &nsec.public_key(),
        time,
        &Kind::TextNote,
        &[],
        &losing_message,
    );

    let oracle_info = OracleInfo {
        public_key: announcement.oracle_public_key,
        nonces: announcement.oracle_event.oracle_nonces,
    };

    let nsec_hex = nsec.secret_key().unwrap().secret_bytes().to_hex();
    let sigs = outcomes
        .into_iter()
        .map(|outcome| {
            let message = vec![Message::from_hashed_data::<sha256::Hash>(
                outcome.as_bytes(),
            )];
            let point =
                dlc::get_adaptor_point_from_oracle_info(&secp, &[oracle_info.clone()], &[message])
                    .unwrap();

            let sig = adaptor_sign(&nsec_hex, point.serialize(), event_id);
            let serialized = bincode::serialize(&sig).unwrap();
            serialized.to_hex()
        })
        .collect::<Vec<_>>();

    sigs
}

pub fn complete_signature(encrypted_sig: String, attestation: String) -> String {
    let bytes: Vec<u8> = FromHex::from_hex(&encrypted_sig).unwrap();
    let encrypted_sig = bincode::deserialize::<EncryptedSignature>(&bytes).unwrap();
    let attestation = oracle_attestation_from_hex(&attestation);
    let (_, s_value) = dlc::secp_utils::schnorrsig_decompose(&attestation.signatures[0]).unwrap();

    let sig = decrypt_signature(s_value, encrypted_sig);
    sig.to_bytes().to_hex()
}

/// Parses a hex string into an oracle announcement.
fn oracle_announcement_from_hex(hex: &str) -> OracleAnnouncement {
    let bytes: Vec<u8> = FromHex::from_hex(hex).unwrap();
    let mut cursor = Cursor::new(bytes);

    OracleAnnouncement::read(&mut cursor).unwrap()
}

/// Parses a hex string into an oracle attestation.
fn oracle_attestation_from_hex(hex: &str) -> OracleAttestation {
    let bytes: Vec<u8> = FromHex::from_hex(hex).unwrap();
    let mut cursor = Cursor::new(bytes);

    OracleAttestation::read(&mut cursor).unwrap()
}

#[cfg(test)]
mod test {
    use crate::{complete_signature, create_tweaked_signatures, oracle_announcement_from_hex};
    use dlc::secp256k1_zkp::hashes::hex::ToHex;
    use nostr::{EventId, Keys, Kind, Timestamp, UnsignedEvent};
    use std::str::FromStr;

    const ANNOUNCEMENT: &str = "00fa6568a68af95dcc8eec11bb92948e09d09fcdb7fc17a0806e3d3087534e4ae9b5de2c5265035ff5e3ebffa39e664b243955a3599280487d46bc045159b3cc5c1ef2cc6453c9b672ecb7186fa59462d69bf7d12052bbe31ac570b36b68e2b3fdd822350001cd026e5319cce1525324702134fe192c0c81f5335b79e3a090f702e144e13e3465a5c700fdd806060002016101620474657374";
    const ATTESTATION: &str = "5c1ef2cc6453c9b672ecb7186fa59462d69bf7d12052bbe31ac570b36b68e2b30001cd026e5319cce1525324702134fe192c0c81f5335b79e3a090f702e144e13e348985893b864fc0e1c68a4a40b45bff0bb378e90d535c5d7ce04e1e2abc6a762800010161";

    #[test]
    fn test() {
        let nsec = Keys::generate();
        let ann = oracle_announcement_from_hex(ANNOUNCEMENT);
        let losing_message = "I lost".to_string();

        let created_at = Timestamp::from(ann.oracle_event.event_maturity_epoch as u64);
        let event_id = EventId::new(
            &nsec.public_key(),
            created_at,
            &Kind::TextNote,
            &[],
            &losing_message,
        );
        let unsigned = UnsignedEvent {
            id: event_id,
            pubkey: nsec.public_key(),
            created_at,
            kind: Kind::TextNote,
            tags: vec![],
            content: losing_message.clone(),
        };

        let sigs = create_tweaked_signatures(
            nsec.secret_key().unwrap().secret_bytes().to_hex(),
            losing_message,
            ANNOUNCEMENT.to_string(),
            vec!["a".to_string()],
        );

        let complete = complete_signature(sigs[0].to_owned(), ATTESTATION.to_string());

        let signature = nostr::secp256k1::schnorr::Signature::from_str(&complete).unwrap();
        assert!(unsigned.add_signature(signature).is_ok())
    }
}
