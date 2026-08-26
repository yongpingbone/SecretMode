pub mod lifecycle;
pub mod replay;

use jni::objects::{JByteArray, JObject};
use jni::sys::{jbyteArray, jstring};
use jni::JNIEnv;
use vodozemac::olm::{Account, OlmMessage, Session, SessionConfig, SessionPickle};

fn establish_probe_sessions() -> Result<(Session, Session), String> {
    let alice = Account::new();
    let mut bob = Account::new();

    bob.generate_one_time_keys(1);
    let bob_otk = *bob
        .one_time_keys()
        .values()
        .next()
        .ok_or_else(|| "one-time key should exist".to_owned())?;

    let mut alice_session = alice
        .create_outbound_session(
            SessionConfig::version_1(),
            bob.curve25519_key(),
            bob_otk,
        )
        .map_err(|error| format!("failed to create outbound Olm session: {error:?}"))?;

    bob.mark_keys_as_published();

    let first_plaintext = b"m0-secretmode-roundtrip";
    let first_encrypted = alice_session
        .encrypt(first_plaintext)
        .map_err(|error| format!("failed to encrypt pre-key message: {error:?}"))?;

    let pre_key = match first_encrypted {
        OlmMessage::PreKey(message) => message,
        OlmMessage::Normal(_) => return Err("first Olm message was not a pre-key message".to_owned()),
    };

    let inbound = bob
        .create_inbound_session(
            SessionConfig::version_1(),
            alice.curve25519_key(),
            &pre_key,
        )
        .map_err(|error| format!("failed to create inbound Olm session: {error:?}"))?;

    if inbound.plaintext.as_slice() != first_plaintext {
        return Err("inbound Olm session did not decrypt the pre-key plaintext".to_owned());
    }

    let mut bob_session = inbound.session;
    if alice_session.session_id() != bob_session.session_id() {
        return Err("Olm peers established different session IDs".to_owned());
    }

    let reply_plaintext = b"m0-reply";
    let reply = bob_session
        .encrypt(reply_plaintext)
        .map_err(|error| format!("failed to encrypt Olm reply: {error:?}"))?;
    let decrypted = alice_session
        .decrypt(&reply)
        .map_err(|error| format!("failed to decrypt Olm reply: {error:?}"))?;
    if decrypted.as_slice() != reply_plaintext {
        return Err("Olm reply plaintext mismatch".to_owned());
    }

    Ok((alice_session, bob_session))
}

fn create_serialized_probe_bundle() -> Result<Vec<u8>, String> {
    let (alice_session, bob_session) = establish_probe_sessions()?;
    serde_json::to_vec(&(alice_session.pickle(), bob_session.pickle()))
        .map_err(|error| format!("failed to serialize Olm SessionPickle bundle: {error}"))
}

fn validate_serialized_probe_bundle(bytes: &[u8]) -> Result<String, String> {
    let (alice_pickle, bob_pickle): (SessionPickle, SessionPickle) = serde_json::from_slice(bytes)
        .map_err(|error| format!("failed to deserialize Olm SessionPickle bundle: {error}"))?;

    let mut alice_session = Session::from_pickle(alice_pickle);
    let mut bob_session = Session::from_pickle(bob_pickle);
    let alice_session_id = alice_session.session_id();
    let bob_session_id = bob_session.session_id();

    if alice_session_id != bob_session_id {
        return Err("restored Olm peers have different session IDs".to_owned());
    }

    let probe_plaintext = b"m0-restored-session-functional-probe";
    let encrypted = alice_session
        .encrypt(probe_plaintext)
        .map_err(|error| format!("restored Olm session could not encrypt: {error:?}"))?;
    let decrypted = bob_session
        .decrypt(&encrypted)
        .map_err(|error| format!("restored Olm peer could not decrypt: {error:?}"))?;

    if decrypted.as_slice() != probe_plaintext {
        return Err("restored Olm session plaintext mismatch".to_owned());
    }

    Ok(alice_session_id)
}

fn throw_illegal_state(env: &mut JNIEnv<'_>, message: impl AsRef<str>) {
    let _ = env.throw_new("java/lang/IllegalStateException", message.as_ref());
}

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

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_yongpingbone_secretmode_crypto_CryptoBridge_nativeCreateOlmPickleBundle<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
) -> jbyteArray {
    let bytes = match create_serialized_probe_bundle() {
        Ok(bytes) => bytes,
        Err(error) => {
            throw_illegal_state(&mut env, error);
            return std::ptr::null_mut();
        }
    };

    match env.byte_array_from_slice(&bytes) {
        Ok(value) => value.into_raw(),
        Err(error) => {
            throw_illegal_state(&mut env, format!("failed to return Olm pickle bytes through JNI: {error:?}"));
            std::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_yongpingbone_secretmode_crypto_CryptoBridge_nativeValidateOlmPickleBundle<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    bundle: JByteArray<'local>,
) -> jstring {
    let bytes = match env.convert_byte_array(&bundle) {
        Ok(bytes) => bytes,
        Err(error) => {
            throw_illegal_state(&mut env, format!("failed to read Olm pickle bytes through JNI: {error:?}"));
            return std::ptr::null_mut();
        }
    };

    let session_id = match validate_serialized_probe_bundle(&bytes) {
        Ok(session_id) => session_id,
        Err(error) => {
            throw_illegal_state(&mut env, error);
            return std::ptr::null_mut();
        }
    };

    match env.new_string(session_id) {
        Ok(value) => value.into_raw(),
        Err(error) => {
            throw_illegal_state(&mut env, format!("failed to return restored Olm session ID through JNI: {error:?}"));
            std::ptr::null_mut()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{create_serialized_probe_bundle, establish_probe_sessions, validate_serialized_probe_bundle};
    use anyhow::Result;
    use vodozemac::olm::{Session, SessionPickle};

    fn establish_sessions() -> Result<(Session, Session)> {
        establish_probe_sessions().map_err(anyhow::Error::msg)
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
    fn serialized_probe_bundle_restores_functional_olm_sessions() -> Result<()> {
        let bundle = create_serialized_probe_bundle().map_err(anyhow::Error::msg)?;
        let session_id = validate_serialized_probe_bundle(&bundle).map_err(anyhow::Error::msg)?;
        assert!(!session_id.is_empty());
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
