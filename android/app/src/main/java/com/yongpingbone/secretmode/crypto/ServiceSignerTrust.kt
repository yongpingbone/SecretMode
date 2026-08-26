package com.yongpingbone.secretmode.crypto

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

enum class ServiceSignerScope(val wireValue: String) {
    STATE_EVENT("STATE_EVENT"),
    LEASE("LEASE"),
}

enum class ServiceSignerStatus(val wireValue: String) {
    ACTIVE("ACTIVE"),
    RETIRED("RETIRED"),
    REVOKED("REVOKED"),
}

class ServiceSigningKey(
    val keyId: String,
    val scope: ServiceSignerScope,
    publicKeySpki: ByteArray,
    val validFromMs: Long,
    val validUntilMs: Long,
    val status: ServiceSignerStatus,
    val disabledAtMs: Long? = null,
) {
    private val publicKeySpkiBytes = publicKeySpki.copyOf()

    val publicKeySpki: ByteArray
        get() = publicKeySpkiBytes.copyOf()

    init {
        val keyIdBytes = keyId.toByteArray(StandardCharsets.UTF_8)
        require(keyIdBytes.size in 8..128) { "service signing keyId must be 8..128 UTF-8 bytes" }
        require(publicKeySpkiBytes.isNotEmpty() && publicKeySpkiBytes.size <= 1024) {
            "service signing public-key SPKI size is invalid"
        }
        require(validFromMs >= 0) { "service signing key validFromMs must not be negative" }
        require(validUntilMs > validFromMs) { "service signing key validity window is invalid" }
        when (status) {
            ServiceSignerStatus.ACTIVE -> require(disabledAtMs == null) {
                "ACTIVE service signing key must not have disabledAtMs"
            }
            ServiceSignerStatus.RETIRED,
            ServiceSignerStatus.REVOKED -> require(
                disabledAtMs != null && disabledAtMs in validFromMs..validUntilMs,
            ) {
                "disabled service signing key requires disabledAtMs inside its validity window"
            }
        }
    }

    internal fun writeCanonicalTo(stream: DataOutputStream) {
        stream.writeLengthPrefixed(keyId.toByteArray(StandardCharsets.UTF_8))
        stream.writeLengthPrefixed(ALGORITHM.toByteArray(StandardCharsets.UTF_8))
        stream.writeLengthPrefixed(scope.wireValue.toByteArray(StandardCharsets.UTF_8))
        stream.writeLengthPrefixed(publicKeySpkiBytes)
        stream.writeLong(validFromMs)
        stream.writeLong(validUntilMs)
        stream.writeLengthPrefixed(status.wireValue.toByteArray(StandardCharsets.UTF_8))
        stream.writeBoolean(disabledAtMs != null)
        if (disabledAtMs != null) {
            stream.writeLong(disabledAtMs)
        }
    }

    internal fun authorizes(requiredScope: ServiceSignerScope, artifactIssuedAtMs: Long): Boolean {
        if (scope != requiredScope) return false
        if (artifactIssuedAtMs < validFromMs || artifactIssuedAtMs >= validUntilMs) return false
        return when (status) {
            ServiceSignerStatus.ACTIVE -> true
            ServiceSignerStatus.RETIRED -> artifactIssuedAtMs < checkNotNull(disabledAtMs)
            ServiceSignerStatus.REVOKED -> false
        }
    }

    companion object {
        const val ALGORITHM = "P256_SHA256_ECDSA"
    }
}

class ServiceSigningKeyset(
    val keysetVersion: Long,
    val rootKeyId: String,
    val issuedAtMs: Long,
    val expiresAtMs: Long,
    keys: List<ServiceSigningKey>,
    val protocolVersion: Int = CURRENT_PROTOCOL_VERSION,
) {
    private val keyEntries = keys.toList()

    val keys: List<ServiceSigningKey>
        get() = keyEntries.toList()

    init {
        require(protocolVersion == CURRENT_PROTOCOL_VERSION) { "unsupported service signer keyset version" }
        require(keysetVersion >= 1) { "keysetVersion must be positive" }
        val rootIdBytes = rootKeyId.toByteArray(StandardCharsets.UTF_8)
        require(rootIdBytes.size in 8..128) { "rootKeyId must be 8..128 UTF-8 bytes" }
        require(issuedAtMs >= 0) { "keyset issuedAtMs must not be negative" }
        require(expiresAtMs > issuedAtMs) { "keyset expiry must be after issuance" }
        require(keyEntries.isNotEmpty() && keyEntries.size <= MAX_KEYS) { "service signer keyset size is invalid" }
        require(keyEntries.map { it.keyId }.toSet().size == keyEntries.size) {
            "service signer key IDs must be unique"
        }
    }

    fun canonicalBytes(): ByteArray {
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { stream ->
            stream.writeLengthPrefixed(KEYSET_DOMAIN.toByteArray(StandardCharsets.UTF_8))
            stream.writeInt(protocolVersion)
            stream.writeLong(keysetVersion)
            stream.writeLengthPrefixed(rootKeyId.toByteArray(StandardCharsets.UTF_8))
            stream.writeLong(issuedAtMs)
            stream.writeLong(expiresAtMs)
            val ordered = keyEntries.sortedBy { it.keyId }
            stream.writeInt(ordered.size)
            ordered.forEach { it.writeCanonicalTo(stream) }
        }
        return output.toByteArray()
    }

    fun digest(): ByteArray = MessageDigest.getInstance("SHA-256").digest(canonicalBytes())

    companion object {
        const val CURRENT_PROTOCOL_VERSION = 1
        const val MAX_KEYS = 64
        private const val KEYSET_DOMAIN = "SecretMode-Service-Signing-Keyset-v1"
    }
}

class SignedServiceSigningKeyset(
    val keyset: ServiceSigningKeyset,
    rootSignature: ByteArray,
) {
    private val rootSignatureBytes = rootSignature.copyOf()

    val rootSignature: ByteArray
        get() = rootSignatureBytes.copyOf()
}

class ServiceSignerTrustSnapshot(
    val highestKeysetVersion: Long,
    highestKeysetDigest: ByteArray,
) {
    private val digestBytes = highestKeysetDigest.copyOf()

    val highestKeysetDigest: ByteArray
        get() = digestBytes.copyOf()

    init {
        require(highestKeysetVersion >= 1) { "persisted keyset version must be positive" }
        require(digestBytes.size == 32) { "persisted keyset digest must be 32 bytes" }
    }
}

class ServiceSignerTrustStore(
    pinnedRootSpkiById: Map<String, ByteArray>,
    private val minimumKeysetVersion: Long,
    persistedSnapshot: ServiceSignerTrustSnapshot? = null,
) {
    private val pinnedRoots = pinnedRootSpkiById.mapValues { (_, value) -> value.copyOf() }
    private var highestKeysetVersion: Long
    private var highestKeysetDigest: ByteArray?
    private var acceptedKeyset: ServiceSigningKeyset? = null

    init {
        require(pinnedRoots.isNotEmpty()) { "at least one service root public key must be pinned" }
        require(minimumKeysetVersion >= 1) { "minimumKeysetVersion must be positive" }
        pinnedRoots.forEach { (rootId, spki) ->
            require(rootId.toByteArray(StandardCharsets.UTF_8).size in 8..128) {
                "pinned service root ID must be 8..128 UTF-8 bytes"
            }
            require(spki.isNotEmpty() && spki.size <= 1024) { "pinned service root SPKI size is invalid" }
        }

        if (persistedSnapshot != null && persistedSnapshot.highestKeysetVersion >= minimumKeysetVersion) {
            highestKeysetVersion = persistedSnapshot.highestKeysetVersion
            highestKeysetDigest = persistedSnapshot.highestKeysetDigest
        } else {
            highestKeysetVersion = minimumKeysetVersion - 1
            highestKeysetDigest = null
        }
    }

    fun acceptKeyset(signedKeyset: SignedServiceSigningKeyset, nowMs: Long): Boolean {
        if (nowMs < 0) return false
        val keyset = signedKeyset.keyset
        if (keyset.keysetVersion < minimumKeysetVersion) return false
        if (nowMs < keyset.issuedAtMs || nowMs >= keyset.expiresAtMs) return false
        val rootSpki = pinnedRoots[keyset.rootKeyId] ?: return false
        if (!verifyP256(rootSpki, keyset.canonicalBytes(), signedKeyset.rootSignature)) return false

        val candidateDigest = keyset.digest()
        if (keyset.keysetVersion < highestKeysetVersion) return false
        if (keyset.keysetVersion == highestKeysetVersion) {
            val expectedDigest = highestKeysetDigest ?: return false
            if (!MessageDigest.isEqual(expectedDigest, candidateDigest)) return false
        }

        if (keyset.keysetVersion > highestKeysetVersion) {
            highestKeysetVersion = keyset.keysetVersion
            highestKeysetDigest = candidateDigest.copyOf()
        }
        acceptedKeyset = keyset
        return true
    }

    fun verifyArtifact(
        signingKeyId: String,
        requiredScope: ServiceSignerScope,
        artifactIssuedAtMs: Long,
        payload: ByteArray,
        signatureBytes: ByteArray,
        nowMs: Long,
    ): Boolean {
        val keyset = acceptedKeyset ?: return false
        if (nowMs < 0 || artifactIssuedAtMs < 0 || artifactIssuedAtMs > nowMs) return false
        if (nowMs < keyset.issuedAtMs || nowMs >= keyset.expiresAtMs) return false
        val key = keyset.keys.firstOrNull { it.keyId == signingKeyId } ?: return false
        if (!key.authorizes(requiredScope, artifactIssuedAtMs)) return false
        return verifyP256(key.publicKeySpki, payload, signatureBytes)
    }

    fun securitySnapshot(): ServiceSignerTrustSnapshot? {
        val digest = highestKeysetDigest ?: return null
        return ServiceSignerTrustSnapshot(highestKeysetVersion, digest)
    }

    companion object {
        fun verifyP256(publicKeySpki: ByteArray, payload: ByteArray, signatureBytes: ByteArray): Boolean = try {
            val publicKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(publicKeySpki))
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(publicKey)
                update(payload)
                verify(signatureBytes)
            }
        } catch (_: GeneralSecurityException) {
            false
        }
    }
}
