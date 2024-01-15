use std::str::FromStr;

use nostr::EventId;
use rand::rngs::ThreadRng;
use schnorr_fun::adaptor::{Adaptor, EncryptedSignature};
use schnorr_fun::fun::marker::{NonZero, Normal, Public};
use schnorr_fun::fun::Point;
use schnorr_fun::{
    adaptor::EncryptedSign,
    fun::{nonce, Scalar},
    Message, Schnorr, Signature,
};
use sha2::Sha256;

pub fn adaptor_sign(nsec: &str, encryption_key: [u8; 33], message: EventId) -> EncryptedSignature {
    let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
    let schnorr = Schnorr::<Sha256, _>::new(nonce_gen);
    let signing_keypair = schnorr.new_keypair(Scalar::from_str(nsec).unwrap());
    let encryption_key: Point<Normal, Public, NonZero> = Point::from_bytes(encryption_key).unwrap();
    let message = Message::<Public>::raw(message.as_bytes());

    schnorr.encrypted_sign(&signing_keypair, &encryption_key, message)
}

pub fn decrypt_signature(s_value: &[u8], encrypted_sig: EncryptedSignature) -> Signature {
    let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
    let schnorr = Schnorr::<Sha256, _>::new(nonce_gen);

    let scalar: Scalar<Public> = Scalar::from_slice(s_value).unwrap().non_zero().unwrap();

    schnorr.decrypt_signature(scalar, encrypted_sig)
}
