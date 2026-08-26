use jni::objects::JObject;
use jni::sys::jstring;
use jni::JNIEnv;

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_yongpingbone_secretmode_crypto_CryptoBridge_nativeProbe<'local>(
    env: JNIEnv<'local>,
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
    use vodozemac::olm::{Account, OlmMessage, Session, SessionConfig, SessionPickle};

    fn establish_sessions() -> Result<(Session, Session)> {
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

        Ok((alice_session, bob_session))
    }

    #[test]
    fn olm_roundtrip_establishes_matching_session() -> Result<()> {
        let (alice_session, bob_session) = establish_sessions()?;
        assert_eq!(alice_session.session_id(), bob_session.session_id());
        assert!(alice_session.has_received_message());
        assert!(bob_session.has_received_message());
        Ok(())
    }

    #[test]
    fn one_thousand_messages_each_direction_roundtrip() -> Result<()> {
        let (mut alice_session, mut bob_session) = establish_sessions()?;

        for index in 0..1_000 {
            let alice_plaintext = format!("alice-{index}").into_bytes();
            let encrypted_for_bob = alice_session.encrypt(&alice_plaintext)?;
            assert_eq!(bob_session.decrypt(&encrypted_for_bob)?, alice_plaintext);

            let bob_plaintext = format!("bob-{index}").into_bytes();
            let encrypted_for_alice = bob_session.encrypt(&bob_plaintext)?;
            assert_eq!(alice_session.decrypt(&encrypted_for_alice)?, bob_plaintext);
        }

        Ok(())
    }

    #[test]
    fn dropped_and_out_of_order_messages_do_not_break_session() -> Result<()> {
        let (mut alice_session, mut bob_session) = establish_sessions()?;

        let mut messages = Vec::new();
        for index in 0..12 {
            let plaintext = format!("queued-{index}").into_bytes();
            let encrypted = alice_session.encrypt(&plaintext)?;
            messages.push((plaintext, encrypted));
        }

        // Simulate two messages being dropped while later messages arrive out of order.
        // The dropped ciphertexts are intentionally never delivered in this test.
        for index in [11usize, 2, 7, 0, 10, 5, 1, 8, 3, 6] {
            let (plaintext, encrypted) = &messages[index];
            assert_eq!(bob_session.decrypt(encrypted)?, *plaintext);
        }

        let reply = b"session-still-healthy-after-gap";
        let encrypted_reply = bob_session.encrypt(reply)?;
        assert_eq!(alice_session.decrypt(&encrypted_reply)?, reply);

        Ok(())
    }

    #[test]
    fn serialized_pickle_survives_simulated_process_death() -> Result<()> {
        let (mut alice_session, mut bob_session) = establish_sessions()?;

        for index in 0..32 {
            let plaintext = format!("before-process-death-{index}").into_bytes();
            let encrypted = alice_session.encrypt(&plaintext)?;
            assert_eq!(bob_session.decrypt(&encrypted)?, plaintext);
        }

        let alice_session_id = alice_session.session_id();
        let bob_session_id = bob_session.session_id();

        // Cross a real serialization boundary before dropping the live session objects.
        // The byte vectors are the only state allowed to survive this simulated process death.
        let alice_bytes = serde_json::to_vec(&alice_session.pickle())?;
        let bob_bytes = serde_json::to_vec(&bob_session.pickle())?;

        drop(alice_session);
        drop(bob_session);

        let alice_pickle: SessionPickle = serde_json::from_slice(&alice_bytes)?;
        let bob_pickle: SessionPickle = serde_json::from_slice(&bob_bytes)?;
        let mut restored_alice = Session::from_pickle(alice_pickle);
        let mut restored_bob = Session::from_pickle(bob_pickle);

        assert_eq!(restored_alice.session_id(), alice_session_id);
        assert_eq!(restored_bob.session_id(), bob_session_id);
        assert_eq!(restored_alice.session_id(), restored_bob.session_id());

        for index in 0..32 {
            let bob_plaintext = format!("after-process-death-bob-{index}").into_bytes();
            let encrypted_for_alice = restored_bob.encrypt(&bob_plaintext)?;
            assert_eq!(restored_alice.decrypt(&encrypted_for_alice)?, bob_plaintext);

            let alice_plaintext = format!("after-process-death-alice-{index}").into_bytes();
            let encrypted_for_bob = restored_alice.encrypt(&alice_plaintext)?;
            assert_eq!(restored_bob.decrypt(&encrypted_for_bob)?, alice_plaintext);
        }

        Ok(())
    }
}
