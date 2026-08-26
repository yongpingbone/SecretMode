package com.yongpingbone.secretmode.crypto

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle
import com.yongpingbone.secretmode.storage.SessionStateCipher
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.MessageDigest

class CryptoProbeInstrumentation : Instrumentation() {
    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        start()
    }

    override fun onStart() {
        val result = Bundle()
        try {
            val probe = CryptoBridge.loadForM0Probe()
            check(probe == "vodozemac-0.10.0") { "Unexpected crypto probe result: $probe" }

            verifyKeystoreCryptographicErasure()
            val restoredSessionId = verifyRealOlmSessionCryptographicErasure()
            verifyDeviceIdentitySigningAndPairingTranscript()
            verifyParticipantRevokeRequestAuthorization()

            result.putString("secretmode_result", "ok")
            result.putString("probe", probe)
            result.putString("keystore_destroy_result", "ok")
            result.putString("olm_pickle_destroy_result", "ok")
            result.putString("restored_olm_session_id", restoredSessionId)
            result.putString("device_identity_result", "ok")
            result.putString("pairing_transcript_result", "ok")
            result.putString("participant_revoke_request_result", "ok")
            finish(Activity.RESULT_OK, result)
        } catch (t: Throwable) {
            result.putString("secretmode_result", "failure")
            result.putString("error_type", t.javaClass.name)
            result.putString("error_message", t.message ?: "unknown")
            finish(Activity.RESULT_CANCELED, result)
        }
    }

    private fun verifyDeviceIdentitySigningAndPairingTranscript() {
        val inviterAlias = "secretmode.m1-device-identity-probe.inviter"
        val inviteeAlias = "secretmode.m1-device-identity-probe.invitee"
        deleteProbeKey(inviterAlias)
        deleteProbeKey(inviteeAlias)

        try {
            val inviterSigner = DeviceIdentitySigner(inviterAlias)
            val inviteeSigner = DeviceIdentitySigner(inviteeAlias)
            val inviterSpki = inviterSigner.publicKeySpki()
            val inviteeSpki = inviteeSigner.publicKeySpki()

            check(inviterSpki.isNotEmpty()) { "Inviter AndroidKeyStore identity SPKI is empty" }
            check(inviteeSpki.isNotEmpty()) { "Invitee AndroidKeyStore identity SPKI is empty" }
            check(!inviterSpki.contentEquals(inviteeSpki)) { "Distinct identity aliases produced the same public key" }
            check(DeviceIdentitySigner(inviterAlias).publicKeySpki().contentEquals(inviterSpki)) {
                "Identity key was not stable when reopened from AndroidKeyStore"
            }

            val identityProbe = "secretmode-m1-device-identity-probe".toByteArray()
            val identitySignature = inviterSigner.sign(identityProbe)
            check(DeviceIdentitySigner.verify(inviterSpki, identityProbe, identitySignature)) {
                "Device identity signature did not verify"
            }
            val tamperedIdentityProbe = identityProbe.copyOf().also { bytes ->
                bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte()
            }
            check(!DeviceIdentitySigner.verify(inviterSpki, tamperedIdentityProbe, identitySignature)) {
                "Device identity signature verified a tampered payload"
            }
            check(!DeviceIdentitySigner.verify(byteArrayOf(1, 2, 3), identityProbe, identitySignature)) {
                "Malformed peer SPKI was not rejected"
            }

            val transcript = PairingTranscript(
                pairingId = ByteArray(PairingTranscript.PAIRING_ID_SIZE_BYTES) { index -> (index + 1).toByte() },
                createdAtMs = 1_700_000_000_000L,
                expiresAtMs = 1_700_000_300_000L,
                inviter = PairingParty(
                    deviceId = "m1-inviter-device",
                    identitySpki = inviterSpki,
                    nonce = ByteArray(PairingParty.NONCE_SIZE_BYTES) { index -> (index + 11).toByte() },
                ),
                invitee = PairingParty(
                    deviceId = "m1-invitee-device",
                    identitySpki = inviteeSpki,
                    nonce = ByteArray(PairingParty.NONCE_SIZE_BYTES) { index -> (index + 71).toByte() },
                ),
            )
            check(transcript.digest().size == 32) { "Pairing transcript SHA-256 digest is not 32 bytes" }

            val inviterPayload = transcript.signingPayload(PairingRole.INVITER)
            val inviteePayload = transcript.signingPayload(PairingRole.INVITEE)
            val inviterSignature = inviterSigner.sign(inviterPayload)
            val inviteeSignature = inviteeSigner.sign(inviteePayload)

            check(DeviceIdentitySigner.verify(inviterSpki, inviterPayload, inviterSignature)) {
                "Inviter pairing transcript signature did not verify"
            }
            check(DeviceIdentitySigner.verify(inviteeSpki, inviteePayload, inviteeSignature)) {
                "Invitee pairing transcript signature did not verify"
            }
            check(!DeviceIdentitySigner.verify(inviteeSpki, inviterPayload, inviterSignature)) {
                "Inviter signature unexpectedly verified under invitee identity key"
            }
            check(!DeviceIdentitySigner.verify(inviterSpki, inviteePayload, inviterSignature)) {
                "Inviter signature was reusable under the invitee role"
            }

            val inviterNonceSnapshot = transcript.inviter.nonce
            val mutatedSnapshot = inviterNonceSnapshot.copyOf().also { bytes ->
                bytes[0] = (bytes[0].toInt() xor 1).toByte()
            }
            check(!mutatedSnapshot.contentEquals(transcript.inviter.nonce)) {
                "PairingParty exposed mutable nonce storage"
            }

            val tamperedTranscript = PairingTranscript(
                pairingId = transcript.pairingId,
                createdAtMs = transcript.createdAtMs,
                expiresAtMs = transcript.expiresAtMs,
                inviter = transcript.inviter,
                invitee = PairingParty(
                    deviceId = "attacker-substituted-device",
                    identitySpki = transcript.invitee.identitySpki,
                    nonce = transcript.invitee.nonce,
                ),
            )
            check(!DeviceIdentitySigner.verify(
                inviterSpki,
                tamperedTranscript.signingPayload(PairingRole.INVITER),
                inviterSignature,
            )) { "Inviter signature verified a peer-substituted transcript" }
            check(!DeviceIdentitySigner.verify(
                inviteeSpki,
                tamperedTranscript.signingPayload(PairingRole.INVITEE),
                inviteeSignature,
            )) { "Invitee signature verified a peer-substituted transcript" }

            identityProbe.fill(0)
            tamperedIdentityProbe.fill(0)
            inviterNonceSnapshot.fill(0)
            mutatedSnapshot.fill(0)
        } finally {
            deleteProbeKey(inviterAlias)
            deleteProbeKey(inviteeAlias)
        }
    }

    private fun verifyParticipantRevokeRequestAuthorization() {
        val requesterAlias = "secretmode.m1-revoke-request-probe.requester"
        val peerAlias = "secretmode.m1-revoke-request-probe.peer"
        deleteProbeKey(requesterAlias)
        deleteProbeKey(peerAlias)

        try {
            val requesterSigner = DeviceIdentitySigner(requesterAlias)
            val peerSigner = DeviceIdentitySigner(peerAlias)
            val requesterSpki = requesterSigner.publicKeySpki()
            val peerSpki = peerSigner.publicKeySpki()
            val digest = MessageDigest.getInstance("SHA-256")
            val relationshipDigest = digest.digest("secretmode-m1-verified-relationship".toByteArray())
            val requesterFingerprint = digest.digest(requesterSpki)
            val requestId = ByteArray(ParticipantRevokeRequest.REQUEST_ID_SIZE_BYTES) { index -> (index + 91).toByte() }

            val request = ParticipantRevokeRequest(
                requestId = requestId,
                sessionId = "session-revoke-probe-0001",
                relationshipTranscriptDigest = relationshipDigest,
                requesterDeviceId = "m1-inviter-device",
                requesterIdentityKeyFingerprint = requesterFingerprint,
                requestedAtMs = 1_700_000_000_000L,
                expiresAtMs = 1_700_000_060_000L,
                reason = ParticipantRevokeReason.USER_REQUESTED,
            )
            val payload = request.signingPayload()
            val signature = requesterSigner.sign(payload)

            check(DeviceIdentitySigner.verify(requesterSpki, payload, signature)) {
                "Participant revoke request signature did not verify"
            }
            check(!DeviceIdentitySigner.verify(peerSpki, payload, signature)) {
                "Participant revoke request verified under the other participant key"
            }

            val tamperedSession = ParticipantRevokeRequest(
                requestId = request.requestId,
                sessionId = "session-revoke-probe-0002",
                relationshipTranscriptDigest = request.relationshipTranscriptDigest,
                requesterDeviceId = request.requesterDeviceId,
                requesterIdentityKeyFingerprint = request.requesterIdentityKeyFingerprint,
                requestedAtMs = request.requestedAtMs,
                expiresAtMs = request.expiresAtMs,
                reason = request.reason,
            )
            check(!DeviceIdentitySigner.verify(requesterSpki, tamperedSession.signingPayload(), signature)) {
                "Revoke signature verified after session substitution"
            }

            val tamperedRelationshipDigest = request.relationshipTranscriptDigest.also { bytes ->
                bytes[0] = (bytes[0].toInt() xor 1).toByte()
            }
            val tamperedRelationship = ParticipantRevokeRequest(
                requestId = request.requestId,
                sessionId = request.sessionId,
                relationshipTranscriptDigest = tamperedRelationshipDigest,
                requesterDeviceId = request.requesterDeviceId,
                requesterIdentityKeyFingerprint = request.requesterIdentityKeyFingerprint,
                requestedAtMs = request.requestedAtMs,
                expiresAtMs = request.expiresAtMs,
                reason = request.reason,
            )
            check(!DeviceIdentitySigner.verify(requesterSpki, tamperedRelationship.signingPayload(), signature)) {
                "Revoke signature verified after relationship substitution"
            }

            val tamperedFingerprint = request.requesterIdentityKeyFingerprint.also { bytes ->
                bytes[0] = (bytes[0].toInt() xor 1).toByte()
            }
            val tamperedIdentity = ParticipantRevokeRequest(
                requestId = request.requestId,
                sessionId = request.sessionId,
                relationshipTranscriptDigest = request.relationshipTranscriptDigest,
                requesterDeviceId = request.requesterDeviceId,
                requesterIdentityKeyFingerprint = tamperedFingerprint,
                requestedAtMs = request.requestedAtMs,
                expiresAtMs = request.expiresAtMs,
                reason = request.reason,
            )
            check(!DeviceIdentitySigner.verify(requesterSpki, tamperedIdentity.signingPayload(), signature)) {
                "Revoke signature verified after requester identity fingerprint substitution"
            }

            val tamperedReason = ParticipantRevokeRequest(
                requestId = request.requestId,
                sessionId = request.sessionId,
                relationshipTranscriptDigest = request.relationshipTranscriptDigest,
                requesterDeviceId = request.requesterDeviceId,
                requesterIdentityKeyFingerprint = request.requesterIdentityKeyFingerprint,
                requestedAtMs = request.requestedAtMs,
                expiresAtMs = request.expiresAtMs,
                reason = ParticipantRevokeReason.SECURITY_RESET,
            )
            check(!DeviceIdentitySigner.verify(requesterSpki, tamperedReason.signingPayload(), signature)) {
                "Revoke signature verified after reason substitution"
            }

            val requestIdSnapshot = request.requestId
            requestIdSnapshot[0] = (requestIdSnapshot[0].toInt() xor 1).toByte()
            check(!requestIdSnapshot.contentEquals(request.requestId)) {
                "ParticipantRevokeRequest exposed mutable requestId storage"
            }
            val relationshipSnapshot = request.relationshipTranscriptDigest
            relationshipSnapshot[0] = (relationshipSnapshot[0].toInt() xor 1).toByte()
            check(!relationshipSnapshot.contentEquals(request.relationshipTranscriptDigest)) {
                "ParticipantRevokeRequest exposed mutable relationship digest storage"
            }
            val fingerprintSnapshot = request.requesterIdentityKeyFingerprint
            fingerprintSnapshot[0] = (fingerprintSnapshot[0].toInt() xor 1).toByte()
            check(!fingerprintSnapshot.contentEquals(request.requesterIdentityKeyFingerprint)) {
                "ParticipantRevokeRequest exposed mutable identity fingerprint storage"
            }

            payload.fill(0)
            relationshipDigest.fill(0)
            requesterFingerprint.fill(0)
            requestId.fill(0)
            tamperedRelationshipDigest.fill(0)
            tamperedFingerprint.fill(0)
            requestIdSnapshot.fill(0)
            relationshipSnapshot.fill(0)
            fingerprintSnapshot.fill(0)
        } finally {
            deleteProbeKey(requesterAlias)
            deleteProbeKey(peerAlias)
        }
    }

    private fun deleteProbeKey(alias: String) {
        KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
            if (containsAlias(alias)) {
                deleteEntry(alias)
            }
        }
    }

    private fun verifyKeystoreCryptographicErasure() {
        val sessionId = "m0-keystore-destruction-probe-session"
        val oldPlaintext = "serialized-olm-pickle-that-must-become-unrecoverable".toByteArray()
        val replacementPlaintext = "replacement-session-state".toByteArray()

        check(SessionStateCipher.destroy(sessionId))
        check(!SessionStateCipher.hasKey(sessionId))

        val oldState = SessionStateCipher.encrypt(sessionId, oldPlaintext)
        check(SessionStateCipher.hasKey(sessionId))
        check(SessionStateCipher.decrypt(sessionId, oldState).contentEquals(oldPlaintext))

        check(SessionStateCipher.destroy(sessionId))
        check(!SessionStateCipher.hasKey(sessionId))

        var missingKeyRejected = false
        try {
            SessionStateCipher.decrypt(sessionId, oldState)
        } catch (_: SessionStateCipher.MissingSessionKeyException) {
            missingKeyRejected = true
        }
        check(missingKeyRejected) { "Old state decrypted after its Keystore key was deleted" }

        val replacementState = SessionStateCipher.encrypt(sessionId, replacementPlaintext)
        check(SessionStateCipher.decrypt(sessionId, replacementState).contentEquals(replacementPlaintext))

        var oldCiphertextRejectedByReplacementKey = false
        try {
            SessionStateCipher.decrypt(sessionId, oldState)
        } catch (_: GeneralSecurityException) {
            oldCiphertextRejectedByReplacementKey = true
        }
        check(oldCiphertextRejectedByReplacementKey) { "Old state unexpectedly decrypted with a replacement Keystore key" }

        oldPlaintext.fill(0)
        replacementPlaintext.fill(0)
        check(SessionStateCipher.destroy(sessionId))
        check(!SessionStateCipher.hasKey(sessionId))
    }

    private fun verifyRealOlmSessionCryptographicErasure(): String {
        val storageSessionId = "m0-real-olm-pickle-destruction-probe"
        var plaintextForCleanup: ByteArray? = null
        var recoveredForCleanup: ByteArray? = null
        var replacementForCleanup: ByteArray? = null

        check(SessionStateCipher.destroy(storageSessionId))
        check(!SessionStateCipher.hasKey(storageSessionId))

        try {
            val createdBundle = CryptoBridge.createM0OlmPickleBundle()
            plaintextForCleanup = createdBundle
            check(createdBundle.isNotEmpty()) { "Rust returned an empty Olm SessionPickle bundle" }

            val originalSessionId = CryptoBridge.validateM0OlmPickleBundle(createdBundle)
            check(originalSessionId.isNotBlank()) { "Restored Olm session ID must not be blank" }

            val encryptedState = SessionStateCipher.encrypt(storageSessionId, createdBundle)
            check(SessionStateCipher.hasKey(storageSessionId))

            val recoveredBundle = SessionStateCipher.decrypt(storageSessionId, encryptedState)
            recoveredForCleanup = recoveredBundle
            val recoveredSessionId = CryptoBridge.validateM0OlmPickleBundle(recoveredBundle)
            check(recoveredSessionId == originalSessionId) { "Keystore roundtrip changed the restored Olm session identity" }

            createdBundle.fill(0)
            plaintextForCleanup = null
            recoveredBundle.fill(0)
            recoveredForCleanup = null

            check(SessionStateCipher.destroy(storageSessionId))
            check(!SessionStateCipher.hasKey(storageSessionId))

            var missingKeyRejected = false
            try {
                SessionStateCipher.decrypt(storageSessionId, encryptedState)
            } catch (_: SessionStateCipher.MissingSessionKeyException) {
                missingKeyRejected = true
            }
            check(missingKeyRejected) { "Destroyed Keystore key still decrypted a real Olm SessionPickle bundle" }

            val replacementPlaintext = "replacement-state-must-not-open-old-olm-pickle".toByteArray()
            replacementForCleanup = replacementPlaintext
            val replacementState = SessionStateCipher.encrypt(storageSessionId, replacementPlaintext)
            check(SessionStateCipher.decrypt(storageSessionId, replacementState).contentEquals(replacementPlaintext))

            var oldCiphertextRejectedByReplacementKey = false
            try {
                SessionStateCipher.decrypt(storageSessionId, encryptedState)
            } catch (_: GeneralSecurityException) {
                oldCiphertextRejectedByReplacementKey = true
            }
            check(oldCiphertextRejectedByReplacementKey) { "Replacement key unexpectedly authenticated ciphertext containing the old Olm SessionPickle" }

            replacementPlaintext.fill(0)
            replacementForCleanup = null
            return originalSessionId
        } finally {
            plaintextForCleanup?.fill(0)
            recoveredForCleanup?.fill(0)
            replacementForCleanup?.fill(0)
            SessionStateCipher.destroy(storageSessionId)
        }
    }
}
