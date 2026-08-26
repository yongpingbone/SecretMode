use jni::objects::JObject;
use jni::sys::jstring;
use jni::JNIEnv;

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_yongpingbone_secretmode_crypto_CryptoBridge_nativeProbe<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
) -> jstring {
    match env.new_string(format!("vodozemac-{}", vodozemac::VERSION)) {
        Ok(value) => value.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use vodozemac::olm::{Account, OlmMessage, SessionConfig};

    #[test]
    fn olm_roundtrip_establishes_matching_session() -> Result<()> {
        let alice = Account::new();
        let mut bob = Account::new();

        bob.generate_one_time_keys(1);
        let bob_otk = *bob
            .one_time_keys()
            .values()
            .next()
            .expect("one-time key should exist");

        let mut alice_session = alice.create_outbound_session(
            SessionConfig::version_1(),
            bob.curve25519_key(),
            bob_otk,
        )?;

        bob.mark_keys_as_published();

        let first_plaintext = b"m0-secretmode-roundtrip";
        let first_encrypted = alice_session.encrypt(first_plaintext)?;

        let pre_key = match first_encrypted {
            OlmMessage::PreKey(message) => message,
            OlmMessage::Normal(_) => panic!("first message must be pre-key"),
        };

        let inbound = bob.create_inbound_session(
            SessionConfig::version_1(),
            alice.curve25519_key(),
            &pre_key,
        )?;

        assert_eq!(inbound.plaintext, first_plaintext);
        let mut bob_session = inbound.session;
        assert_eq!(alice_session.session_id(), bob_session.session_id());

        let reply_plaintext = b"m0-reply";
        let reply = bob_session.encrypt(reply_plaintext)?;
        let decrypted = alice_session.decrypt(&reply)?;
        assert_eq!(decrypted, reply_plaintext);

        Ok(())
    }
}
