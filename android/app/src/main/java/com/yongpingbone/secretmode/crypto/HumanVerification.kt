package com.yongpingbone.secretmode.crypto

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.charset.StandardCharsets
import java.util.Base64

enum class HumanVerificationMethod(val wireValue: String) {
    IN_PERSON_QR_SCAN("in_person_qr_scan"),
    IN_PERSON_PEER_CONFIRM("in_person_peer_confirm"),
}

class FinalVerificationQr private constructor(
    pairingId: ByteArray,
    transcriptDigest: ByteArray,
) {
    private val pairingIdBytes = pairingId.copyOf()
    private val transcriptDigestBytes = transcriptDigest.copyOf()

    val pairingId: ByteArray
        get() = pairingIdBytes.copyOf()

    val transcriptDigest: ByteArray
        get() = transcriptDigestBytes.copyOf()

    init {
        require(pairingIdBytes.size == PairingTranscript.PAIRING_ID_SIZE_BYTES) {
            "final verification QR pairingId must be 16 bytes"
        }
        require(transcriptDigestBytes.size == TRANSCRIPT_DIGEST_SIZE_BYTES) {
            "final verification QR transcript digest must be 32 bytes"
        }
    }

    fun encode(): String = buildString {
        append(PREFIX)
        append('.')
        append(base64Url(pairingIdBytes))
        append('.')
        append(base64Url(transcriptDigestBytes))
    }

    fun matches(transcript: PairingTranscript): Boolean =
        pairingIdBytes.contentEquals(transcript.pairingId) &&
            transcriptDigestBytes.contentEquals(transcript.digest())

    companion object {
        private const val PREFIX = "SMV1"
        private const val TRANSCRIPT_DIGEST_SIZE_BYTES = 32

        fun fromTranscript(transcript: PairingTranscript): FinalVerificationQr =
            FinalVerificationQr(transcript.pairingId, transcript.digest())

        fun parse(encoded: String): FinalVerificationQr {
            require(encoded == encoded.trim()) { "final verification QR must not contain surrounding whitespace" }
            val parts = encoded.split('.')
            require(parts.size == 3 && parts[0] == PREFIX) { "unsupported final verification QR format" }

            val pairingId = decodeCanonicalBase64Url(parts[1], PairingTranscript.PAIRING_ID_SIZE_BYTES)
            val transcriptDigest = decodeCanonicalBase64Url(parts[2], TRANSCRIPT_DIGEST_SIZE_BYTES)
            return FinalVerificationQr(pairingId, transcriptDigest)
        }

        private fun decodeCanonicalBase64Url(value: String, expectedSize: Int): ByteArray {
            require(value.isNotEmpty()) { "final verification QR field must not be empty" }
            val decoded = try {
                Base64.getUrlDecoder().decode(value)
            } catch (e: IllegalArgumentException) {
                throw IllegalArgumentException("invalid final verification QR base64url", e)
            }
            require(decoded.size == expectedSize) { "final verification QR field has invalid size" }
            require(base64Url(decoded) == value) { "final verification QR field is not canonical base64url" }
            return decoded
        }

        private fun base64Url(bytes: ByteArray): String =
            Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }
}

class HumanVerificationAckPayload(
    pairingId: ByteArray,
    transcriptDigest: ByteArray,
    val verifierRole: PairingRole,
    val verifierDeviceId: String,
    val method: HumanVerificationMethod,
    val verifiedAtMs: Long,
    val protocolVersion: Int = CURRENT_PROTOCOL_VERSION,
) {
    private val pairingIdBytes = pairingId.copyOf()
    private val transcriptDigestBytes = transcriptDigest.copyOf()

    val pairingId: ByteArray
        get() = pairingIdBytes.copyOf()

    val transcriptDigest: ByteArray
        get() = transcriptDigestBytes.copyOf()

    init {
        require(protocolVersion == CURRENT_PROTOCOL_VERSION) { "unsupported human verification protocol version" }
        require(pairingIdBytes.size == PairingTranscript.PAIRING_ID_SIZE_BYTES) { "pairingId must be 16 bytes" }
        require(transcriptDigestBytes.size == TRANSCRIPT_DIGEST_SIZE_BYTES) { "transcript digest must be 32 bytes" }
        require(verifierDeviceId.isNotBlank()) { "verifierDeviceId must not be blank" }
        require(verifierDeviceId.toByteArray(StandardCharsets.UTF_8).size <= 128) { "verifierDeviceId is too long" }
        require(verifiedAtMs >= 0) { "verifiedAtMs must not be negative" }
    }

    fun signingPayload(): ByteArray = encodeFields {
        writeLengthPrefixed(ACK_DOMAIN.toByteArray(StandardCharsets.UTF_8))
        writeInt(protocolVersion)
        writeLengthPrefixed(pairingIdBytes)
        writeLengthPrefixed(transcriptDigestBytes)
        writeLengthPrefixed(verifierRole.wireValue.toByteArray(StandardCharsets.UTF_8))
        writeLengthPrefixed(verifierDeviceId.toByteArray(StandardCharsets.UTF_8))
        writeLengthPrefixed(method.wireValue.toByteArray(StandardCharsets.UTF_8))
        writeLong(verifiedAtMs)
    }

    private fun encodeFields(block: DataOutputStream.() -> Unit): ByteArray {
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { stream -> stream.block() }
        return output.toByteArray()
    }

    companion object {
        const val CURRENT_PROTOCOL_VERSION = 1
        const val TRANSCRIPT_DIGEST_SIZE_BYTES = 32
        private const val ACK_DOMAIN = "SecretMode-Human-Verification-Ack-v1"
    }
}

class SignedHumanVerificationAcknowledgment(
    val payload: HumanVerificationAckPayload,
    signatureDer: ByteArray,
) {
    private val signatureBytes = signatureDer.copyOf()

    val signatureDer: ByteArray
        get() = signatureBytes.copyOf()

    init {
        require(signatureBytes.isNotEmpty() && signatureBytes.size <= 256) {
            "human verification signature size is invalid"
        }
    }
}

object HumanVerificationGate {
    fun signAcknowledgment(
        transcript: PairingTranscript,
        role: PairingRole,
        method: HumanVerificationMethod,
        verifiedAtMs: Long,
        signer: DeviceIdentitySigner,
    ): SignedHumanVerificationAcknowledgment {
        val party = partyForRole(transcript, role)
        require(signer.publicKeySpki().contentEquals(party.identitySpki)) {
            "signer does not match the transcript identity for verifier role"
        }
        val payload = HumanVerificationAckPayload(
            pairingId = transcript.pairingId,
            transcriptDigest = transcript.digest(),
            verifierRole = role,
            verifierDeviceId = party.deviceId,
            method = method,
            verifiedAtMs = verifiedAtMs,
        )
        return SignedHumanVerificationAcknowledgment(
            payload = payload,
            signatureDer = signer.sign(payload.signingPayload()),
        )
    }

    fun verifyAcknowledgment(
        transcript: PairingTranscript,
        acknowledgment: SignedHumanVerificationAcknowledgment,
    ): Boolean {
        val payload = acknowledgment.payload
        if (!payload.pairingId.contentEquals(transcript.pairingId)) return false
        if (!payload.transcriptDigest.contentEquals(transcript.digest())) return false
        if (payload.verifiedAtMs < transcript.createdAtMs || payload.verifiedAtMs >= transcript.expiresAtMs) return false

        val party = partyForRole(transcript, payload.verifierRole)
        if (payload.verifierDeviceId != party.deviceId) return false

        return DeviceIdentitySigner.verify(
            party.identitySpki,
            payload.signingPayload(),
            acknowledgment.signatureDer,
        )
    }

    fun isVerified(
        transcript: PairingTranscript,
        acknowledgments: Collection<SignedHumanVerificationAcknowledgment>,
    ): Boolean {
        val valid = acknowledgments.filter { verifyAcknowledgment(transcript, it) }
        val qrScans = valid.filter { it.payload.method == HumanVerificationMethod.IN_PERSON_QR_SCAN }
        val peerConfirms = valid.filter { it.payload.method == HumanVerificationMethod.IN_PERSON_PEER_CONFIRM }

        return qrScans.any { scan ->
            peerConfirms.any { confirm ->
                scan.payload.verifierRole != confirm.payload.verifierRole &&
                    scan.payload.verifierDeviceId != confirm.payload.verifierDeviceId
            }
        }
    }

    private fun partyForRole(transcript: PairingTranscript, role: PairingRole): PairingParty = when (role) {
        PairingRole.INVITER -> transcript.inviter
        PairingRole.INVITEE -> transcript.invitee
    }
}
