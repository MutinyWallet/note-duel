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

fn decode_bytes(str: &str) -> Result<Vec<u8>, Error> {
    match FromHex::from_hex(str) {
        Ok(bytes) => Ok(bytes),
        Err(_) => Ok(base64::decode(str)?),
    }
}

/// Parses a string into an oracle announcement.
pub(crate) fn oracle_announcement_from_str(str: &str) -> Result<OracleAnnouncement, Error> {
    let bytes = decode_bytes(str)?;
    let mut cursor = Cursor::new(bytes);

    Ok(OracleAnnouncement::read(&mut cursor)?)
}

/// Parses a string into an oracle attestation.
pub(crate) fn oracle_attestation_from_str(str: &str) -> Result<OracleAttestation, Error> {
    let bytes = decode_bytes(str)?;
    let mut cursor = Cursor::new(bytes);

    Ok(OracleAttestation::read(&mut cursor)?)
}
