package com.yongpingbone.secretmode.crypto

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

enum class PairingRole(val wireValue: String) {
    INVITER("inviter"),
    INVITEE("invitee"),
}

class PairingParty(
    val deviceId: String,
    identitySpki: ByteArray,
    nonce: ByteArray,
) {
    private val identitySpkiBytes = identitySpki.copyOf()
    private val nonceBytes = nonce.copyOf()

    val identitySpki: ByteArray
        get() = identitySpkiBytes.copyOf()

    val nonce: ByteArray
        get() = nonceBytes.copyOf()

    init {
        require(deviceId.isNotBlank()) { "deviceId must not be blank" }
        require(deviceId.toByteArray(StandardCharsets.UTF_8).size <= 128) { "deviceId is too long" }
        require(identitySpkiBytes.isNotEmpty() && identitySpkiBytes.size <= 1024) { "identity SPKI size is invalid" }
        require(nonceBytes.size == NONCE_SIZE_BYTES) { "pairing nonce must be 32 bytes" }
    }

    internal fun writeCanonicalTo(stream: DataOutputStream) {
        stream.writeLengthPrefixed(deviceId.toByteArray(StandardCharsets.UTF_8))
        stream.writeLengthPrefixed(identitySpkiBytes)
        stream.writeLengthPrefixed(nonceBytes)
    }

    companion object {
        const val NONCE_SIZE_BYTES = 32
    }
}

class PairingTranscript(
    pairingId: ByteArray,
    val createdAtMs: Long,
    val expiresAtMs: Long,
    val inviter: PairingParty,
    val invitee: PairingParty,
    val protocolVersion: Int = CURRENT_PROTOCOL_VERSION,
) {
    private val pairingIdBytes = pairingId.copyOf()

    val pairingId: ByteArray
        get() = pairingIdBytes.copyOf()

    init {
        require(protocolVersion == CURRENT_PROTOCOL_VERSION) { "unsupported pairing protocol version" }
        require(pairingIdBytes.size == PAIRING_ID_SIZE_BYTES) { "pairingId must be 16 bytes" }
        require(createdAtMs >= 0) { "createdAtMs must not be negative" }
        require(expiresAtMs > createdAtMs) { "pairing transcript expiry must be after creation" }
        require(!inviter.identitySpki.contentEquals(invitee.identitySpki)) {
            "pairing peers must use distinct device identity keys"
        }
    }

    fun canonicalBytes(): ByteArray = encodeFields {
        writeLengthPrefixed(TRANSCRIPT_DOMAIN.toByteArray(StandardCharsets.UTF_8))
        writeInt(protocolVersion)
        writeLengthPrefixed(pairingIdBytes)
        writeLong(createdAtMs)
        writeLong(expiresAtMs)
        inviter.writeCanonicalTo(this)
        invitee.writeCanonicalTo(this)
    }

    fun digest(): ByteArray = MessageDigest.getInstance("SHA-256").digest(canonicalBytes())

    fun signingPayload(role: PairingRole): ByteArray = encodeFields {
        writeLengthPrefixed(SIGNATURE_DOMAIN.toByteArray(StandardCharsets.UTF_8))
        writeLengthPrefixed(role.wireValue.toByteArray(StandardCharsets.UTF_8))
        writeLengthPrefixed(canonicalBytes())
    }

    private fun encodeFields(block: DataOutputStream.() -> Unit): ByteArray {
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { stream ->
            stream.block()
        }
        return output.toByteArray()
    }

    companion object {
        const val CURRENT_PROTOCOL_VERSION = 1
        const val PAIRING_ID_SIZE_BYTES = 16
        private const val TRANSCRIPT_DOMAIN = "SecretMode-Pairing-Transcript-v1"
        private const val SIGNATURE_DOMAIN = "SecretMode-Pairing-Signature-v1"
    }
}

internal fun DataOutputStream.writeLengthPrefixed(bytes: ByteArray) {
    writeInt(bytes.size)
    write(bytes)
}
