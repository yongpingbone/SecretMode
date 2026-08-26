package com.yongpingbone.secretmode.debug

import android.app.Activity
import android.graphics.Color
import android.os.Bundle
import android.util.Log
import com.yongpingbone.secretmode.crypto.DeviceIdentitySigner
import com.yongpingbone.secretmode.crypto.PairingParty
import com.yongpingbone.secretmode.crypto.PairingRole
import com.yongpingbone.secretmode.crypto.PairingTranscript
import com.yongpingbone.secretmode.verification.FinalVerificationActivity
import com.yongpingbone.secretmode.verification.FinalVerificationQrRenderer
import com.yongpingbone.secretmode.verification.FinalVerificationSession
import com.yongpingbone.secretmode.verification.FinalVerificationSessionRegistry
import java.security.KeyStore

class FinalVerificationUxProbeActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        try {
            verifyFinalVerificationUxCore()
            Log.i(TAG, "final_verification_ux_result=ok")
        } catch (t: Throwable) {
            Log.e(TAG, "final_verification_ux_result=failure type=${t.javaClass.name} message=${t.message}", t)
        } finally {
            FinalVerificationSessionRegistry.clearForTests()
            finish()
        }
    }

    private fun verifyFinalVerificationUxCore() {
        val inviterAlias = "secretmode.m1-final-ux.inviter"
        val inviteeAlias = "secretmode.m1-final-ux.invitee"
        deleteProbeKey(inviterAlias)
        deleteProbeKey(inviteeAlias)
        FinalVerificationSessionRegistry.clearForTests()

        try {
            val inviterSigner = DeviceIdentitySigner(inviterAlias)
            val inviteeSigner = DeviceIdentitySigner(inviteeAlias)
            val now = System.currentTimeMillis()
            val transcript = PairingTranscript(
                pairingId = ByteArray(PairingTranscript.PAIRING_ID_SIZE_BYTES) { index -> (index + 101).toByte() },
                createdAtMs = now - 1_000,
                expiresAtMs = now + 300_000,
                inviter = PairingParty(
                    deviceId = "final-ux-inviter",
                    identitySpki = inviterSigner.publicKeySpki(),
                    nonce = ByteArray(PairingParty.NONCE_SIZE_BYTES) { index -> (index + 11).toByte() },
                ),
                invitee = PairingParty(
                    deviceId = "final-ux-invitee",
                    identitySpki = inviteeSigner.publicKeySpki(),
                    nonce = ByteArray(PairingParty.NONCE_SIZE_BYTES) { index -> (index + 71).toByte() },
                ),
            )
            val inviterSession = FinalVerificationSession(transcript, PairingRole.INVITER, inviterSigner)
            val inviteeSession = FinalVerificationSession(transcript, PairingRole.INVITEE, inviteeSigner)

            val qrPayload = inviterSession.qrPayload()
            check(qrPayload.startsWith("SMV1.")) { "production final QR payload version is missing" }
            val bitmap = FinalVerificationQrRenderer.render(qrPayload, 256)
            check(bitmap.width == 256 && bitmap.height == 256) { "final QR bitmap dimensions are wrong" }
            var blackPixels = 0
            var whitePixels = 0
            for (y in 0 until bitmap.height) {
                for (x in 0 until bitmap.width) {
                    when (bitmap.getPixel(x, y)) {
                        Color.BLACK -> blackPixels++
                        Color.WHITE -> whitePixels++
                    }
                }
            }
            check(blackPixels > 0 && whitePixels > 0) { "final QR bitmap did not contain both modules and background" }
            bitmap.recycle()

            val inviterOutbound = mutableListOf<com.yongpingbone.secretmode.crypto.SignedHumanVerificationAcknowledgment>()
            val token = FinalVerificationSessionRegistry.register(inviterSession) { acknowledgment ->
                inviterOutbound += acknowledgment
            }
            val entry = checkNotNull(FinalVerificationSessionRegistry.get(token)) {
                "registered final verification session token was not retrievable"
            }
            val intent = FinalVerificationActivity.createIntent(this, token)
            check(intent.component?.className == FinalVerificationActivity::class.java.name) {
                "final verification intent did not target the production activity"
            }

            val inviteeScan = inviteeSession.acknowledgeScannedQr(qrPayload, now + 10_000)
            check(!inviteeSession.isVerified()) { "QR scan alone reached VERIFIED" }

            val inviterConfirm = entry.session.confirmPeerInPerson(now + 20_000)
            entry.publishLocalAcknowledgment(inviterConfirm)
            check(inviterOutbound.size == 1 && inviterOutbound.single() === inviterConfirm) {
                "production session registry did not publish the local signed acknowledgment"
            }
            check(!inviterSession.isVerified()) { "local peer confirmation alone reached VERIFIED" }

            inviterSession.ingestRemoteAcknowledgment(inviteeScan)
            inviteeSession.ingestRemoteAcknowledgment(inviterConfirm)
            check(inviterSession.isVerified()) { "display-side session did not become VERIFIED after remote scan acknowledgment" }
            check(inviteeSession.isVerified()) { "scan-side session did not become VERIFIED after remote peer confirmation" }

            var reflectedLocalAckRejected = false
            try {
                inviterSession.ingestRemoteAcknowledgment(inviterConfirm)
            } catch (_: IllegalArgumentException) {
                reflectedLocalAckRejected = true
            }
            check(reflectedLocalAckRejected) { "transport-reflected local acknowledgment was accepted as remote" }

            val qrParts = qrPayload.split('.').toMutableList()
            val digestPart = qrParts[2]
            qrParts[2] = (if (digestPart.first() == 'A') 'B' else 'A') + digestPart.drop(1)
            var tamperedQrRejected = false
            try {
                FinalVerificationSession(transcript, PairingRole.INVITEE, inviteeSigner)
                    .acknowledgeScannedQr(qrParts.joinToString("."), now + 30_000)
            } catch (_: IllegalArgumentException) {
                tamperedQrRejected = true
            }
            check(tamperedQrRejected) { "tampered final QR was accepted by production UX session" }

            check(FinalVerificationSessionRegistry.remove(token) != null) {
                "final verification session token was not removable"
            }
            check(FinalVerificationSessionRegistry.get(token) == null) {
                "removed final verification session remained restorable"
            }
        } finally {
            FinalVerificationSessionRegistry.clearForTests()
            deleteProbeKey(inviterAlias)
            deleteProbeKey(inviteeAlias)
        }
    }

    private fun deleteProbeKey(alias: String) {
        KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
            if (containsAlias(alias)) deleteEntry(alias)
        }
    }

    companion object {
        private const val TAG = "SecretModeFinalVerificationUx"
    }
}
