package com.yongpingbone.secretmode.debug

import android.app.Activity
import android.os.Bundle
import android.util.Log
import com.yongpingbone.secretmode.crypto.DeviceIdentitySigner
import com.yongpingbone.secretmode.crypto.FinalVerificationQr
import com.yongpingbone.secretmode.crypto.HumanVerificationAckPayload
import com.yongpingbone.secretmode.crypto.HumanVerificationGate
import com.yongpingbone.secretmode.crypto.HumanVerificationMethod
import com.yongpingbone.secretmode.crypto.PairingParty
import com.yongpingbone.secretmode.crypto.PairingRole
import com.yongpingbone.secretmode.crypto.PairingTranscript
import com.yongpingbone.secretmode.crypto.SignedHumanVerificationAcknowledgment
import java.security.KeyStore

class HumanVerificationProbeActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        try {
            verifyHumanVerificationGate()
            Log.i(TAG, "human_verification_result=ok")
        } catch (t: Throwable) {
            Log.e(TAG, "human_verification_result=failure type=${t.javaClass.name} message=${t.message}", t)
        } finally {
            finish()
        }
    }

    private fun verifyHumanVerificationGate() {
        val inviterAlias = "secretmode.m1-human-verification.inviter"
        val inviteeAlias = "secretmode.m1-human-verification.invitee"
        val replacementAlias = "secretmode.m1-human-verification.replacement"
        deleteProbeKey(inviterAlias)
        deleteProbeKey(inviteeAlias)
        deleteProbeKey(replacementAlias)

        try {
            val inviterSigner = DeviceIdentitySigner(inviterAlias)
            val inviteeSigner = DeviceIdentitySigner(inviteeAlias)
            val replacementSigner = DeviceIdentitySigner(replacementAlias)
            val transcript = transcript(inviterSigner, inviteeSigner)

            val encodedQr = FinalVerificationQr.fromTranscript(transcript).encode()
            check(encodedQr.startsWith("SMV1.")) { "final QR version prefix is missing" }
            val parsedQr = FinalVerificationQr.parse(encodedQr)
            check(parsedQr.matches(transcript)) { "final QR did not round-trip to the final transcript" }
            check(parsedQr.pairingId.size == PairingTranscript.PAIRING_ID_SIZE_BYTES)
            check(parsedQr.transcriptDigest.size == HumanVerificationAckPayload.TRANSCRIPT_DIGEST_SIZE_BYTES)

            val tamperedQrParts = encodedQr.split('.').toMutableList()
            val digestPart = tamperedQrParts[2]
            val replacement = if (digestPart.first() == 'A') 'B' else 'A'
            tamperedQrParts[2] = replacement + digestPart.drop(1)
            val tamperedQr = FinalVerificationQr.parse(tamperedQrParts.joinToString("."))
            check(!tamperedQr.matches(transcript)) { "tampered final QR still matched transcript" }

            var whitespaceRejected = false
            try {
                FinalVerificationQr.parse(" $encodedQr")
            } catch (_: IllegalArgumentException) {
                whitespaceRejected = true
            }
            check(whitespaceRejected) { "non-canonical final QR whitespace was accepted" }

            val inviteeScan = HumanVerificationGate.signAcknowledgment(
                transcript = transcript,
                role = PairingRole.INVITEE,
                method = HumanVerificationMethod.IN_PERSON_QR_SCAN,
                verifiedAtMs = transcript.createdAtMs + 10_000,
                signer = inviteeSigner,
            )
            val inviterConfirm = HumanVerificationGate.signAcknowledgment(
                transcript = transcript,
                role = PairingRole.INVITER,
                method = HumanVerificationMethod.IN_PERSON_PEER_CONFIRM,
                verifiedAtMs = transcript.createdAtMs + 20_000,
                signer = inviterSigner,
            )

            check(HumanVerificationGate.verifyAcknowledgment(transcript, inviteeScan)) {
                "valid QR-scan acknowledgment was rejected"
            }
            check(HumanVerificationGate.verifyAcknowledgment(transcript, inviterConfirm)) {
                "valid peer-confirm acknowledgment was rejected"
            }
            check(!HumanVerificationGate.isVerified(transcript, listOf(inviteeScan))) {
                "one human acknowledgment was enough to reach VERIFIED"
            }
            check(!HumanVerificationGate.isVerified(transcript, listOf(inviterConfirm))) {
                "one peer-confirm acknowledgment was enough to reach VERIFIED"
            }
            check(HumanVerificationGate.isVerified(transcript, listOf(inviteeScan, inviterConfirm))) {
                "two role-separated human acknowledgments did not reach VERIFIED"
            }

            val duplicateInviteeConfirm = HumanVerificationGate.signAcknowledgment(
                transcript = transcript,
                role = PairingRole.INVITEE,
                method = HumanVerificationMethod.IN_PERSON_PEER_CONFIRM,
                verifiedAtMs = transcript.createdAtMs + 30_000,
                signer = inviteeSigner,
            )
            check(!HumanVerificationGate.isVerified(transcript, listOf(inviteeScan, duplicateInviteeConfirm))) {
                "same participant satisfied both human verification roles"
            }

            val tamperedPayload = HumanVerificationAckPayload(
                pairingId = inviteeScan.payload.pairingId,
                transcriptDigest = inviteeScan.payload.transcriptDigest.also { bytes ->
                    bytes[0] = (bytes[0].toInt() xor 1).toByte()
                },
                verifierRole = inviteeScan.payload.verifierRole,
                verifierDeviceId = inviteeScan.payload.verifierDeviceId,
                method = inviteeScan.payload.method,
                verifiedAtMs = inviteeScan.payload.verifiedAtMs,
            )
            val tamperedAck = SignedHumanVerificationAcknowledgment(
                payload = tamperedPayload,
                signatureDer = inviteeScan.signatureDer,
            )
            check(!HumanVerificationGate.verifyAcknowledgment(transcript, tamperedAck)) {
                "human acknowledgment signature survived transcript-digest substitution"
            }

            val expiredPayload = HumanVerificationAckPayload(
                pairingId = transcript.pairingId,
                transcriptDigest = transcript.digest(),
                verifierRole = PairingRole.INVITEE,
                verifierDeviceId = transcript.invitee.deviceId,
                method = HumanVerificationMethod.IN_PERSON_QR_SCAN,
                verifiedAtMs = transcript.expiresAtMs,
            )
            val expiredAck = SignedHumanVerificationAcknowledgment(
                payload = expiredPayload,
                signatureDer = inviteeSigner.sign(expiredPayload.signingPayload()),
            )
            check(!HumanVerificationGate.verifyAcknowledgment(transcript, expiredAck)) {
                "acknowledgment at pairing expiry was accepted"
            }

            var wrongSignerRejected = false
            try {
                HumanVerificationGate.signAcknowledgment(
                    transcript = transcript,
                    role = PairingRole.INVITER,
                    method = HumanVerificationMethod.IN_PERSON_PEER_CONFIRM,
                    verifiedAtMs = transcript.createdAtMs + 40_000,
                    signer = inviteeSigner,
                )
            } catch (_: IllegalArgumentException) {
                wrongSignerRejected = true
            }
            check(wrongSignerRejected) { "wrong participant key signed a role-bound acknowledgment" }

            val changedKeyTranscript = PairingTranscript(
                pairingId = transcript.pairingId,
                createdAtMs = transcript.createdAtMs,
                expiresAtMs = transcript.expiresAtMs,
                inviter = PairingParty(
                    deviceId = transcript.inviter.deviceId,
                    identitySpki = replacementSigner.publicKeySpki(),
                    nonce = transcript.inviter.nonce,
                ),
                invitee = transcript.invitee,
            )
            check(!HumanVerificationGate.isVerified(changedKeyTranscript, listOf(inviteeScan, inviterConfirm))) {
                "old human acknowledgments silently transferred to a changed device key"
            }

            val pairingIdSnapshot = inviteeScan.payload.pairingId
            pairingIdSnapshot[0] = (pairingIdSnapshot[0].toInt() xor 1).toByte()
            check(!pairingIdSnapshot.contentEquals(inviteeScan.payload.pairingId)) {
                "human verification pairingId exposed mutable backing storage"
            }
            val digestSnapshot = inviteeScan.payload.transcriptDigest
            digestSnapshot[0] = (digestSnapshot[0].toInt() xor 1).toByte()
            check(!digestSnapshot.contentEquals(inviteeScan.payload.transcriptDigest)) {
                "human verification transcript digest exposed mutable backing storage"
            }
            val signatureSnapshot = inviteeScan.signatureDer
            signatureSnapshot[0] = (signatureSnapshot[0].toInt() xor 1).toByte()
            check(!signatureSnapshot.contentEquals(inviteeScan.signatureDer)) {
                "human verification signature exposed mutable backing storage"
            }
        } finally {
            deleteProbeKey(inviterAlias)
            deleteProbeKey(inviteeAlias)
            deleteProbeKey(replacementAlias)
        }
    }

    private fun transcript(
        inviterSigner: DeviceIdentitySigner,
        inviteeSigner: DeviceIdentitySigner,
    ): PairingTranscript = PairingTranscript(
        pairingId = ByteArray(PairingTranscript.PAIRING_ID_SIZE_BYTES) { index -> (index + 31).toByte() },
        createdAtMs = 1_700_100_000_000L,
        expiresAtMs = 1_700_100_300_000L,
        inviter = PairingParty(
            deviceId = "human-verification-inviter",
            identitySpki = inviterSigner.publicKeySpki(),
            nonce = ByteArray(PairingParty.NONCE_SIZE_BYTES) { index -> (index + 41).toByte() },
        ),
        invitee = PairingParty(
            deviceId = "human-verification-invitee",
            identitySpki = inviteeSigner.publicKeySpki(),
            nonce = ByteArray(PairingParty.NONCE_SIZE_BYTES) { index -> (index + 81).toByte() },
        ),
    )

    private fun deleteProbeKey(alias: String) {
        KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
            if (containsAlias(alias)) deleteEntry(alias)
        }
    }

    companion object {
        private const val TAG = "SecretModeHumanVerification"
    }
}
