package com.yongpingbone.secretmode.verification

import com.yongpingbone.secretmode.crypto.SignedHumanVerificationAcknowledgment
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

object FinalVerificationSessionRegistry {
    class Entry internal constructor(
        val session: FinalVerificationSession,
        private val onLocalAcknowledgment: (SignedHumanVerificationAcknowledgment) -> Unit,
    ) {
        fun publishLocalAcknowledgment(acknowledgment: SignedHumanVerificationAcknowledgment) {
            require(acknowledgment.payload.verifierRole == session.localRole) {
                "cannot publish an acknowledgment for a non-local pairing role"
            }
            onLocalAcknowledgment(acknowledgment)
        }
    }

    private val sessions = ConcurrentHashMap<String, Entry>()

    fun register(
        session: FinalVerificationSession,
        onLocalAcknowledgment: (SignedHumanVerificationAcknowledgment) -> Unit,
    ): String {
        while (true) {
            val token = UUID.randomUUID().toString()
            if (sessions.putIfAbsent(token, Entry(session, onLocalAcknowledgment)) == null) {
                return token
            }
        }
    }

    fun get(token: String): Entry? = sessions[token]

    fun remove(token: String): Entry? = sessions.remove(token)

    fun clearForTests() {
        sessions.clear()
    }
}
