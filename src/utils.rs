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

#[cfg(test)]
pub async fn sleep(millis: i32) {
    use wasm_bindgen_futures::js_sys;
    let mut cb = |resolve: js_sys::Function, _reject: js_sys::Function| {
        web_sys::window()
            .unwrap()
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, millis)
            .unwrap();
    };
    let p = js_sys::Promise::new(&mut cb);
    wasm_bindgen_futures::JsFuture::from(p).await.unwrap();
}
