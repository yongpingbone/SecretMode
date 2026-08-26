package com.yongpingbone.secretmode.crypto

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

class ServiceSignerTrustInstrumentation : Instrumentation() {
    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        start()
    }

    override fun onStart() {
        val result = Bundle()
        try {
            verifyServiceSignerTrustAndRotation()
            result.putString("service_signer_trust_result", "ok")
            finish(Activity.RESULT_OK, result)
        } catch (t: Throwable) {
            result.putString("service_signer_trust_result", "failure")
            result.putString("error_type", t.javaClass.name)
            result.putString("error_message", t.message ?: "unknown")
            finish(Activity.RESULT_CANCELED, result)
        }
    }

    private fun verifyServiceSignerTrustAndRotation() {
        val now = 1_700_000_100_000L
        val root1 = generateP256KeyPair()
        val root2 = generateP256KeyPair()
        val relayRoot = generateP256KeyPair()
        val stateV1 = generateP256KeyPair()
        val stateV2 = generateP256KeyPair()
        val leaseV1 = generateP256KeyPair()
        val retiredState = generateP256KeyPair()
        val revokedState = generateP256KeyPair()
        val futureState = generateP256KeyPair()
        val rogueLeaf = generateP256KeyPair()

        val root1Id = "service-root-v1"
        val root2Id = "service-root-v2"
        val pinnedRoots = mapOf(
            root1Id to root1.public.encoded,
            root2Id to root2.public.encoded,
        )

        val stateV1Entry = ServiceSigningKey(
            keyId = "state-key-v1",
            scope = ServiceSignerScope.STATE_EVENT,
            publicKeySpki = stateV1.public.encoded,
            validFromMs = now - 60_000,
            validUntilMs = now + 3_600_000,
            status = ServiceSignerStatus.ACTIVE,
        )
        val leaseV1Entry = ServiceSigningKey(
            keyId = "lease-key-v1",
            scope = ServiceSignerScope.LEASE,
            publicKeySpki = leaseV1.public.encoded,
            validFromMs = now - 60_000,
            validUntilMs = now + 3_600_000,
            status = ServiceSignerStatus.ACTIVE,
        )
        val retiredEntry = ServiceSigningKey(
            keyId = "state-retired-v0",
            scope = ServiceSignerScope.STATE_EVENT,
            publicKeySpki = retiredState.public.encoded,
            validFromMs = now - 3_600_000,
            validUntilMs = now + 3_600_000,
            status = ServiceSignerStatus.RETIRED,
            disabledAtMs = now - 30_000,
        )
        val revokedEntry = ServiceSigningKey(
            keyId = "state-revoked-v0",
            scope = ServiceSignerScope.STATE_EVENT,
            publicKeySpki = revokedState.public.encoded,
            validFromMs = now - 3_600_000,
            validUntilMs = now + 3_600_000,
            status = ServiceSignerStatus.REVOKED,
            disabledAtMs = now - 30_000,
        )
        val futureEntry = ServiceSigningKey(
            keyId = "state-future-v2",
            scope = ServiceSignerScope.STATE_EVENT,
            publicKeySpki = futureState.public.encoded,
            validFromMs = now + 60_000,
            validUntilMs = now + 3_600_000,
            status = ServiceSignerStatus.ACTIVE,
        )

        val keysetV1 = ServiceSigningKeyset(
            keysetVersion = 10,
            rootKeyId = root1Id,
            issuedAtMs = now - 1_000,
            expiresAtMs = now + 600_000,
            keys = listOf(stateV1Entry, leaseV1Entry, retiredEntry, revokedEntry, futureEntry),
        )
        val signedV1 = SignedServiceSigningKeyset(
            keysetV1,
            sign(root1.private, keysetV1.canonicalBytes()),
        )
        val trust = ServiceSignerTrustStore(
            pinnedRootSpkiById = pinnedRoots,
            minimumKeysetVersion = 10,
        )
        check(trust.acceptKeyset(signedV1, now)) { "Root-signed service keyset was rejected" }

        val reorderedV1 = ServiceSigningKeyset(
            keysetVersion = keysetV1.keysetVersion,
            rootKeyId = keysetV1.rootKeyId,
            issuedAtMs = keysetV1.issuedAtMs,
            expiresAtMs = keysetV1.expiresAtMs,
            keys = keysetV1.keys.reversed(),
        )
        check(reorderedV1.canonicalBytes().contentEquals(keysetV1.canonicalBytes())) {
            "Service keyset canonical encoding depended on input key order"
        }

        val statePayload = "authoritative-state-event".toByteArray()
        val stateSignature = sign(stateV1.private, statePayload)
        check(trust.verifyArtifact(
            signingKeyId = stateV1Entry.keyId,
            requiredScope = ServiceSignerScope.STATE_EVENT,
            artifactIssuedAtMs = now - 500,
            payload = statePayload,
            signatureBytes = stateSignature,
            nowMs = now,
        )) { "Active state-event leaf did not verify" }
        check(!trust.verifyArtifact(
            signingKeyId = stateV1Entry.keyId,
            requiredScope = ServiceSignerScope.LEASE,
            artifactIssuedAtMs = now - 500,
            payload = statePayload,
            signatureBytes = stateSignature,
            nowMs = now,
        )) { "State-event leaf was accepted for lease scope" }

        val leasePayload = "bounded-display-lease".toByteArray()
        val leaseSignature = sign(leaseV1.private, leasePayload)
        check(trust.verifyArtifact(
            signingKeyId = leaseV1Entry.keyId,
            requiredScope = ServiceSignerScope.LEASE,
            artifactIssuedAtMs = now - 500,
            payload = leasePayload,
            signatureBytes = leaseSignature,
            nowMs = now,
        )) { "Active lease leaf did not verify" }
        check(!trust.verifyArtifact(
            signingKeyId = leaseV1Entry.keyId,
            requiredScope = ServiceSignerScope.STATE_EVENT,
            artifactIssuedAtMs = now - 500,
            payload = leasePayload,
            signatureBytes = leaseSignature,
            nowMs = now,
        )) { "Lease leaf was accepted for state-event scope" }

        val retiredPayload = "historical-retired-state".toByteArray()
        val retiredSignature = sign(retiredState.private, retiredPayload)
        check(trust.verifyArtifact(
            signingKeyId = retiredEntry.keyId,
            requiredScope = ServiceSignerScope.STATE_EVENT,
            artifactIssuedAtMs = now - 60_000,
            payload = retiredPayload,
            signatureBytes = retiredSignature,
            nowMs = now,
        )) { "Retired leaf could not verify a pre-retirement historical artifact" }
        check(!trust.verifyArtifact(
            signingKeyId = retiredEntry.keyId,
            requiredScope = ServiceSignerScope.STATE_EVENT,
            artifactIssuedAtMs = now - 10_000,
            payload = retiredPayload,
            signatureBytes = retiredSignature,
            nowMs = now,
        )) { "Retired leaf verified an artifact issued after retirement" }

        val revokedPayload = "revoked-state-artifact".toByteArray()
        val revokedSignature = sign(revokedState.private, revokedPayload)
        check(!trust.verifyArtifact(
            signingKeyId = revokedEntry.keyId,
            requiredScope = ServiceSignerScope.STATE_EVENT,
            artifactIssuedAtMs = now - 60_000,
            payload = revokedPayload,
            signatureBytes = revokedSignature,
            nowMs = now,
        )) { "Revoked leaf verified a backdated artifact" }

        val futurePayload = "future-key-artifact".toByteArray()
        val futureSignature = sign(futureState.private, futurePayload)
        check(!trust.verifyArtifact(
            signingKeyId = futureEntry.keyId,
            requiredScope = ServiceSignerScope.STATE_EVENT,
            artifactIssuedAtMs = now,
            payload = futurePayload,
            signatureBytes = futureSignature,
            nowMs = now,
        )) { "Future leaf verified before validFromMs" }

        val roguePayload = "relay-minted-artifact".toByteArray()
        val rogueSignature = sign(rogueLeaf.private, roguePayload)
        check(!trust.verifyArtifact(
            signingKeyId = "relay-leaf-01",
            requiredScope = ServiceSignerScope.STATE_EVENT,
            artifactIssuedAtMs = now,
            payload = roguePayload,
            signatureBytes = rogueSignature,
            nowMs = now,
        )) { "Relay-controlled leaf outside the root-signed keyset was trusted" }

        val tamperedRootSignature = signedV1.rootSignature.also { bytes ->
            bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte()
        }
        val freshTrust = ServiceSignerTrustStore(pinnedRoots, minimumKeysetVersion = 10)
        check(!freshTrust.acceptKeyset(SignedServiceSigningKeyset(keysetV1, tamperedRootSignature), now)) {
            "Tampered offline-root signature was accepted"
        }

        val tamperedKeyset = ServiceSigningKeyset(
            keysetVersion = keysetV1.keysetVersion,
            rootKeyId = keysetV1.rootKeyId,
            issuedAtMs = keysetV1.issuedAtMs,
            expiresAtMs = keysetV1.expiresAtMs + 1,
            keys = keysetV1.keys,
        )
        check(!ServiceSignerTrustStore(pinnedRoots, 10).acceptKeyset(
            SignedServiceSigningKeyset(tamperedKeyset, signedV1.rootSignature),
            now,
        )) { "Root signature verified a modified keyset" }

        val rotationAt = now + 60_000
        val stateV2Entry = ServiceSigningKey(
            keyId = "state-key-v2",
            scope = ServiceSignerScope.STATE_EVENT,
            publicKeySpki = stateV2.public.encoded,
            validFromMs = rotationAt,
            validUntilMs = now + 7_200_000,
            status = ServiceSignerStatus.ACTIVE,
        )
        val oldStateRetired = ServiceSigningKey(
            keyId = stateV1Entry.keyId,
            scope = ServiceSignerScope.STATE_EVENT,
            publicKeySpki = stateV1.public.encoded,
            validFromMs = stateV1Entry.validFromMs,
            validUntilMs = stateV1Entry.validUntilMs,
            status = ServiceSignerStatus.RETIRED,
            disabledAtMs = rotationAt,
        )
        val keysetV2 = ServiceSigningKeyset(
            keysetVersion = 11,
            rootKeyId = root1Id,
            issuedAtMs = rotationAt - 1_000,
            expiresAtMs = rotationAt + 600_000,
            keys = listOf(oldStateRetired, stateV2Entry, leaseV1Entry, retiredEntry, revokedEntry),
        )
        val signedV2 = SignedServiceSigningKeyset(
            keysetV2,
            sign(root1.private, keysetV2.canonicalBytes()),
        )
        val afterRotation = rotationAt + 1_000
        check(trust.acceptKeyset(signedV2, afterRotation)) { "Higher-version leaf rotation keyset was rejected" }
        check(trust.verifyArtifact(
            signingKeyId = oldStateRetired.keyId,
            requiredScope = ServiceSignerScope.STATE_EVENT,
            artifactIssuedAtMs = rotationAt - 1,
            payload = statePayload,
            signatureBytes = stateSignature,
            nowMs = afterRotation,
        )) { "Retired old leaf could not verify a pre-rotation artifact" }
        check(!trust.verifyArtifact(
            signingKeyId = oldStateRetired.keyId,
            requiredScope = ServiceSignerScope.STATE_EVENT,
            artifactIssuedAtMs = rotationAt,
            payload = statePayload,
            signatureBytes = stateSignature,
            nowMs = afterRotation,
        )) { "Retired old leaf verified an artifact at/after its disable time" }

        val stateV2Payload = "authoritative-state-event-v2".toByteArray()
        val stateV2Signature = sign(stateV2.private, stateV2Payload)
        check(trust.verifyArtifact(
            signingKeyId = stateV2Entry.keyId,
            requiredScope = ServiceSignerScope.STATE_EVENT,
            artifactIssuedAtMs = afterRotation,
            payload = stateV2Payload,
            signatureBytes = stateV2Signature,
            nowMs = afterRotation,
        )) { "Rotated state-event leaf did not verify" }
        check(!trust.acceptKeyset(signedV1, afterRotation)) { "Keyset rollback was accepted" }

        val conflictingV2Entry = ServiceSigningKey(
            keyId = stateV2Entry.keyId,
            scope = ServiceSignerScope.STATE_EVENT,
            publicKeySpki = rogueLeaf.public.encoded,
            validFromMs = stateV2Entry.validFromMs,
            validUntilMs = stateV2Entry.validUntilMs,
            status = ServiceSignerStatus.ACTIVE,
        )
        val conflictingV2 = ServiceSigningKeyset(
            keysetVersion = keysetV2.keysetVersion,
            rootKeyId = root1Id,
            issuedAtMs = keysetV2.issuedAtMs,
            expiresAtMs = keysetV2.expiresAtMs,
            keys = listOf(oldStateRetired, conflictingV2Entry, leaseV1Entry, retiredEntry, revokedEntry),
        )
        val signedConflictingV2 = SignedServiceSigningKeyset(
            conflictingV2,
            sign(root1.private, conflictingV2.canonicalBytes()),
        )
        check(!trust.acceptKeyset(signedConflictingV2, afterRotation)) {
            "Same-version keyset equivocation was accepted"
        }

        val persistedSnapshot = checkNotNull(trust.securitySnapshot())
        val restoredTrust = ServiceSignerTrustStore(
            pinnedRootSpkiById = pinnedRoots,
            minimumKeysetVersion = 10,
            persistedSnapshot = persistedSnapshot,
        )
        check(!restoredTrust.acceptKeyset(signedV1, afterRotation)) {
            "Process-death restore lost the keyset rollback floor"
        }
        check(restoredTrust.acceptKeyset(signedV2, afterRotation)) {
            "Process-death restore did not accept the exact persisted keyset"
        }
        check(restoredTrust.verifyArtifact(
            signingKeyId = stateV2Entry.keyId,
            requiredScope = ServiceSignerScope.STATE_EVENT,
            artifactIssuedAtMs = afterRotation,
            payload = stateV2Payload,
            signatureBytes = stateV2Signature,
            nowMs = afterRotation,
        )) { "Restored trust state could not verify the accepted rotated signer" }

        val rootRotationAt = rotationAt + 120_000
        val keysetV3 = ServiceSigningKeyset(
            keysetVersion = 12,
            rootKeyId = root2Id,
            issuedAtMs = rootRotationAt - 1_000,
            expiresAtMs = rootRotationAt + 600_000,
            keys = listOf(oldStateRetired, stateV2Entry, leaseV1Entry, retiredEntry, revokedEntry),
        )
        val signedV3 = SignedServiceSigningKeyset(
            keysetV3,
            sign(root2.private, keysetV3.canonicalBytes()),
        )
        val afterRootRotation = rootRotationAt + 1_000
        check(trust.acceptKeyset(signedV3, afterRootRotation)) {
            "Pre-pinned next offline root could not authorize a staged root rotation"
        }

        val root1OnlyTrust = ServiceSignerTrustStore(
            pinnedRootSpkiById = mapOf(root1Id to root1.public.encoded),
            minimumKeysetVersion = 10,
            persistedSnapshot = persistedSnapshot,
        )
        check(!root1OnlyTrust.acceptKeyset(signedV3, afterRootRotation)) {
            "Unpinned next root was trusted without an app trust-anchor update"
        }

        val relayKeyset = ServiceSigningKeyset(
            keysetVersion = 13,
            rootKeyId = "relay-root-01",
            issuedAtMs = afterRootRotation - 1_000,
            expiresAtMs = afterRootRotation + 600_000,
            keys = listOf(
                ServiceSigningKey(
                    keyId = "relay-leaf-01",
                    scope = ServiceSignerScope.STATE_EVENT,
                    publicKeySpki = rogueLeaf.public.encoded,
                    validFromMs = afterRootRotation - 1_000,
                    validUntilMs = afterRootRotation + 600_000,
                    status = ServiceSignerStatus.ACTIVE,
                ),
            ),
        )
        val relaySignedKeyset = SignedServiceSigningKeyset(
            relayKeyset,
            sign(relayRoot.private, relayKeyset.canonicalBytes()),
        )
        check(!trust.acceptKeyset(relaySignedKeyset, afterRootRotation)) {
            "Relay-generated root and keyset became an implicit signing authority"
        }

        check(!trust.verifyArtifact(
            signingKeyId = stateV2Entry.keyId,
            requiredScope = ServiceSignerScope.STATE_EVENT,
            artifactIssuedAtMs = afterRootRotation,
            payload = stateV2Payload,
            signatureBytes = stateV2Signature,
            nowMs = keysetV3.expiresAtMs,
        )) { "Expired service keyset continued authorizing artifacts" }

        statePayload.fill(0)
        leasePayload.fill(0)
        retiredPayload.fill(0)
        revokedPayload.fill(0)
        futurePayload.fill(0)
        roguePayload.fill(0)
        stateV2Payload.fill(0)
        tamperedRootSignature.fill(0)
    }

    private fun generateP256KeyPair(): KeyPair = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1"))
        generateKeyPair()
    }

    private fun sign(privateKey: PrivateKey, payload: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(payload)
            sign()
        }
}
