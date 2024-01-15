use dlc::secp256k1_zkp::hashes::hex::FromHex;
use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
use lightning::util::ser::Readable;
use std::io::Cursor;

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Parses a hex string into an oracle announcement.
pub(crate) fn oracle_announcement_from_hex(hex: &str) -> OracleAnnouncement {
    let bytes: Vec<u8> = FromHex::from_hex(hex).unwrap();
    let mut cursor = Cursor::new(bytes);

    OracleAnnouncement::read(&mut cursor).unwrap()
}

/// Parses a hex string into an oracle attestation.
pub(crate) fn oracle_attestation_from_hex(hex: &str) -> OracleAttestation {
    let bytes: Vec<u8> = FromHex::from_hex(hex).unwrap();
    let mut cursor = Cursor::new(bytes);

    OracleAttestation::read(&mut cursor).unwrap()
}
