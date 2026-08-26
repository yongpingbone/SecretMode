package com.yongpingbone.secretmode.crypto

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.charset.StandardCharsets

enum class ParticipantRevokeReason(val wireValue: String) {
    USER_REQUESTED("USER_REQUESTED"),
    DEVICE_REMOVED("DEVICE_REMOVED"),
    SECURITY_RESET("SECURITY_RESET"),
}

class ParticipantRevokeRequest(
    requestId: ByteArray,
    val sessionId: String,
    relationshipTranscriptDigest: ByteArray,
    val requesterDeviceId: String,
    requesterIdentityKeyFingerprint: ByteArray,
    val requestedAtMs: Long,
    val expiresAtMs: Long,
    val reason: ParticipantRevokeReason,
    val protocolVersion: Int = CURRENT_PROTOCOL_VERSION,
) {
    private val requestIdBytes = requestId.copyOf()
    private val relationshipTranscriptDigestBytes = relationshipTranscriptDigest.copyOf()
    private val requesterIdentityKeyFingerprintBytes = requesterIdentityKeyFingerprint.copyOf()

    val requestId: ByteArray
        get() = requestIdBytes.copyOf()

    val relationshipTranscriptDigest: ByteArray
        get() = relationshipTranscriptDigestBytes.copyOf()

    val requesterIdentityKeyFingerprint: ByteArray
        get() = requesterIdentityKeyFingerprintBytes.copyOf()

    init {
        require(protocolVersion == CURRENT_PROTOCOL_VERSION) { "unsupported revoke request protocol version" }
        require(requestIdBytes.size == REQUEST_ID_SIZE_BYTES) { "revoke requestId must be 16 bytes" }
        val sessionIdBytes = sessionId.toByteArray(StandardCharsets.UTF_8)
        require(sessionIdBytes.size in MIN_SESSION_ID_BYTES..MAX_SESSION_ID_BYTES) { "sessionId UTF-8 size is invalid" }
        require(relationshipTranscriptDigestBytes.size == DIGEST_SIZE_BYTES) { "relationship transcript digest must be 32 bytes" }
        require(requesterDeviceId.isNotBlank()) { "requesterDeviceId must not be blank" }
        require(requesterDeviceId.toByteArray(StandardCharsets.UTF_8).size <= MAX_DEVICE_ID_BYTES) { "requesterDeviceId is too long" }
        require(requesterIdentityKeyFingerprintBytes.size == DIGEST_SIZE_BYTES) { "requester identity fingerprint must be 32 bytes" }
        require(requestedAtMs >= 0) { "requestedAtMs must not be negative" }
        require(expiresAtMs > requestedAtMs) { "revoke request expiry must be after requestedAtMs" }
    }

    fun signingPayload(): ByteArray {
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { stream ->
            stream.writeLengthPrefixed(SIGNATURE_DOMAIN.toByteArray(StandardCharsets.UTF_8))
            stream.writeInt(protocolVersion)
            stream.writeLengthPrefixed(requestIdBytes)
            stream.writeLengthPrefixed(sessionId.toByteArray(StandardCharsets.UTF_8))
            stream.writeLengthPrefixed(relationshipTranscriptDigestBytes)
            stream.writeLengthPrefixed(requesterDeviceId.toByteArray(StandardCharsets.UTF_8))
            stream.writeLengthPrefixed(requesterIdentityKeyFingerprintBytes)
            stream.writeLong(requestedAtMs)
            stream.writeLong(expiresAtMs)
            stream.writeLengthPrefixed(reason.wireValue.toByteArray(StandardCharsets.UTF_8))
        }
        return output.toByteArray()
    }

    companion object {
        const val CURRENT_PROTOCOL_VERSION = 1
        const val REQUEST_ID_SIZE_BYTES = 16
        const val DIGEST_SIZE_BYTES = 32
        private const val MIN_SESSION_ID_BYTES = 16
        private const val MAX_SESSION_ID_BYTES = 256
        private const val MAX_DEVICE_ID_BYTES = 128
        private const val SIGNATURE_DOMAIN = "SecretMode-Participant-Revoke-Request-v1"
    }
}
