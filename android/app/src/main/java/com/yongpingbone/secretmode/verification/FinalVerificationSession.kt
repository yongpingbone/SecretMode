package com.yongpingbone.secretmode.verification

import com.yongpingbone.secretmode.crypto.DeviceIdentitySigner
import com.yongpingbone.secretmode.crypto.FinalVerificationQr
import com.yongpingbone.secretmode.crypto.HumanVerificationGate
import com.yongpingbone.secretmode.crypto.HumanVerificationMethod
import com.yongpingbone.secretmode.crypto.PairingParty
import com.yongpingbone.secretmode.crypto.PairingRole
import com.yongpingbone.secretmode.crypto.PairingTranscript
import com.yongpingbone.secretmode.crypto.SignedHumanVerificationAcknowledgment

class FinalVerificationSession(
    val transcript: PairingTranscript,
    val localRole: PairingRole,
    private val signer: DeviceIdentitySigner,
) {
    private val acknowledgments = mutableListOf<SignedHumanVerificationAcknowledgment>()

    init {
        val localParty = partyForRole(localRole)
        require(signer.publicKeySpki().contentEquals(localParty.identitySpki)) {
            "final verification signer does not match local transcript identity"
        }
    }

    fun qrPayload(): String = FinalVerificationQr.fromTranscript(transcript).encode()

    @Synchronized
    fun acknowledgeScannedQr(
        encodedQr: String,
        verifiedAtMs: Long,
    ): SignedHumanVerificationAcknowledgment {
        requireActive(verifiedAtMs)
        val parsed = FinalVerificationQr.parse(encodedQr)
        require(parsed.matches(transcript)) {
            "scanned final verification QR does not match this pairing transcript"
        }
        return addLocalAcknowledgment(
            HumanVerificationGate.signAcknowledgment(
                transcript = transcript,
                role = localRole,
                method = HumanVerificationMethod.IN_PERSON_QR_SCAN,
                verifiedAtMs = verifiedAtMs,
                signer = signer,
            ),
        )
    }

    @Synchronized
    fun confirmPeerInPerson(verifiedAtMs: Long): SignedHumanVerificationAcknowledgment {
        requireActive(verifiedAtMs)
        return addLocalAcknowledgment(
            HumanVerificationGate.signAcknowledgment(
                transcript = transcript,
                role = localRole,
                method = HumanVerificationMethod.IN_PERSON_PEER_CONFIRM,
                verifiedAtMs = verifiedAtMs,
                signer = signer,
            ),
        )
    }

    @Synchronized
    fun ingestRemoteAcknowledgment(
        acknowledgment: SignedHumanVerificationAcknowledgment,
    ) {
        require(acknowledgment.payload.verifierRole != localRole) {
            "remote acknowledgment cannot claim the local pairing role"
        }
        require(HumanVerificationGate.verifyAcknowledgment(transcript, acknowledgment)) {
            "remote human verification acknowledgment is invalid"
        }
        replaceAcknowledgment(acknowledgment)
    }

    @Synchronized
    fun isVerified(): Boolean = HumanVerificationGate.isVerified(transcript, acknowledgments)

    @Synchronized
    fun hasLocalAcknowledgment(method: HumanVerificationMethod): Boolean = acknowledgments.any {
        it.payload.verifierRole == localRole && it.payload.method == method
    }

    @Synchronized
    fun hasRemoteAcknowledgment(method: HumanVerificationMethod): Boolean = acknowledgments.any {
        it.payload.verifierRole != localRole && it.payload.method == method
    }

    @Synchronized
    fun acknowledgmentSnapshot(): List<SignedHumanVerificationAcknowledgment> = acknowledgments.toList()

    fun localParty(): PairingParty = partyForRole(localRole)

    fun remoteParty(): PairingParty = partyForRole(
        when (localRole) {
            PairingRole.INVITER -> PairingRole.INVITEE
            PairingRole.INVITEE -> PairingRole.INVITER
        },
    )

    private fun requireActive(nowMs: Long) {
        require(nowMs >= transcript.createdAtMs && nowMs < transcript.expiresAtMs) {
            "pairing transcript is not active for human verification"
        }
    }

    private fun addLocalAcknowledgment(
        acknowledgment: SignedHumanVerificationAcknowledgment,
    ): SignedHumanVerificationAcknowledgment {
        check(acknowledgment.payload.verifierRole == localRole)
        check(HumanVerificationGate.verifyAcknowledgment(transcript, acknowledgment))
        replaceAcknowledgment(acknowledgment)
        return acknowledgment
    }

    private fun replaceAcknowledgment(
        acknowledgment: SignedHumanVerificationAcknowledgment,
    ) {
        acknowledgments.removeAll {
            it.payload.verifierRole == acknowledgment.payload.verifierRole &&
                it.payload.method == acknowledgment.payload.method
        }
        acknowledgments += acknowledgment
    }

    private fun partyForRole(role: PairingRole): PairingParty = when (role) {
        PairingRole.INVITER -> transcript.inviter
        PairingRole.INVITEE -> transcript.invitee
    }
}
