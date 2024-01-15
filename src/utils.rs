use crate::error::Error;
use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
use lightning::util::ser::Readable;
use nostr::prelude::hex::FromHex;
use std::io::Cursor;

#[cfg(target_arch = "wasm32")]
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
pub(crate) fn oracle_announcement_from_hex(hex: &str) -> Result<OracleAnnouncement, Error> {
    let bytes: Vec<u8> = FromHex::from_hex(hex)?;
    let mut cursor = Cursor::new(bytes);

    Ok(OracleAnnouncement::read(&mut cursor)?)
}

/// Parses a hex string into an oracle attestation.
pub(crate) fn oracle_attestation_from_hex(hex: &str) -> Result<OracleAttestation, Error> {
    let bytes: Vec<u8> = FromHex::from_hex(hex)?;
    let mut cursor = Cursor::new(bytes);

    Ok(OracleAttestation::read(&mut cursor)?)
}
