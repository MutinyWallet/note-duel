use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    /// Invalid Arguments were given
    #[error("Invalid Arguments were given")]
    InvalidArguments,
    /// Error during signing
    #[error("Error during signing")]
    Signing,
    /// Error getting nostr events
    #[error("Error getting nostr events")]
    Nostr,
}

impl From<nostr::key::Error> for Error {
    fn from(value: nostr::key::Error) -> Self {
        match value {
            nostr::key::Error::InvalidSecretKey => Self::InvalidArguments,
            nostr::key::Error::InvalidPublicKey => Self::InvalidArguments,
            nostr::key::Error::SkMissing => Self::InvalidArguments,
            nostr::key::Error::InvalidChar(_) => Self::InvalidArguments,
            nostr::key::Error::Secp256k1(_) => Self::Signing,
        }
    }
}

impl From<nostr::prelude::hex::Error> for Error {
    fn from(_: nostr::prelude::hex::Error) -> Self {
        Self::InvalidArguments
    }
}

impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self::InvalidArguments
    }
}

impl From<base64::DecodeError> for Error {
    fn from(_: base64::DecodeError) -> Self {
        Self::InvalidArguments
    }
}

impl From<nostr_sdk::client::Error> for Error {
    fn from(_: nostr_sdk::client::Error) -> Self {
        Self::Nostr
    }
}

impl From<dlc::Error> for Error {
    fn from(e: dlc::Error) -> Self {
        match e {
            dlc::Error::Secp256k1(_) => Self::Signing,
            dlc::Error::Sighash(_) => Self::Signing,
            dlc::Error::InvalidArgument => Self::InvalidArguments,
            dlc::Error::Miniscript(_) => Self::Signing,
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl From<Box<bincode::ErrorKind>> for Error {
    fn from(_: Box<bincode::ErrorKind>) -> Self {
        Self::InvalidArguments
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
impl From<lightning::ln::msgs::DecodeError> for Error {
    fn from(_: lightning::ln::msgs::DecodeError) -> Self {
        Self::InvalidArguments
    }
}

#[cfg(target_arch = "wasm32")]
impl From<Error> for wasm_bindgen::JsValue {
    fn from(e: Error) -> Self {
        wasm_bindgen::JsValue::from(e.to_string())
    }
}
