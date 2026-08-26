package com.holin.android.hardening.state

import java.security.SecureRandom
import org.gradle.api.provider.Property
import org.gradle.api.services.BuildService
import org.gradle.api.services.BuildServiceParameters

abstract class InvocationSaltService : BuildService<InvocationSaltService.Parameters>, AutoCloseable {
    interface Parameters : BuildServiceParameters {
        val fixedSeedSha256: Property<String>
    }

    private val invocationSalt by lazy {
        InvocationSalt(PerInvocationSecureEntropy(), parameters.fixedSeedSha256.orNull)
    }

    internal fun bind(context: ReproducibilityContext) = invocationSalt.bind(context)

    fun <T> withSalt(action: (ByteArray) -> T): T = invocationSalt.withSalt(action)

    fun sha256(): String = invocationSalt.sha256()

    fun invocationIdSha256(): String = invocationSalt.invocationIdSha256()

    fun stateReproducibility(): StateReproducibility = invocationSalt.stateReproducibility()

    override fun close() = invocationSalt.close()
}

internal class InvocationSalt(
    private val entropy: EntropySource = PerInvocationSecureEntropy(),
    private val fixedSeedSha256: String? = null,
) : AutoCloseable {
    private val invocationId = entropy.nextBytes("invocation-id", SALT_SIZE).also {
        require(it.size == SALT_SIZE) { "invocation identity entropy must return $SALT_SIZE bytes" }
    }
    private var bytes = if (fixedSeedSha256 == null) {
        entropy.nextBytes("content-salt", SALT_SIZE).also {
            require(it.size == SALT_SIZE) { "content salt entropy must return $SALT_SIZE bytes" }
        }
    } else {
        null
    }
    private var context: ReproducibilityContext? = null
    private var reproducibility: StateReproducibility? = null
    private var closed = false

    @Synchronized
    fun bind(requested: ReproducibilityContext) {
        check(!closed) { "content salt is closed" }
        val existing = context
        check(existing == null || existing == requested) {
            "fixed content salt was already bound to another reproducibility context"
        }
        if (existing != null || fixedSeedSha256 == null) return
        context = requested
        bytes = FixedSeedDerivation.derive(
            fixedSeedSha256,
            requested,
            ReproducibilityPurpose.CONTENT_SALT,
        )
        reproducibility = StateReproducibility.fixed(fixedSeedSha256, requested)
    }

    @Synchronized
    fun <T> withSalt(action: (ByteArray) -> T): T {
        check(!closed) { "content salt is closed" }
        val temporary = activeBytes().copyOf()
        return try {
            action(temporary)
        } finally {
            temporary.fill(0)
        }
    }

    @Synchronized
    fun sha256(): String {
        check(!closed) { "content salt is closed" }
        return Sha256.hex(activeBytes())
    }

    @Synchronized
    fun invocationIdSha256(): String {
        check(!closed) { "content salt is closed" }
        return Sha256.hex(invocationId)
    }

    @Synchronized
    fun stateReproducibility(): StateReproducibility {
        check(!closed) { "content salt is closed" }
        return reproducibility ?: if (fixedSeedSha256 == null) {
            StateReproducibility.secureRandom()
        } else {
            error("fixed content salt has not been bound to a reproducibility context")
        }
    }

    @Synchronized
    override fun close() {
        if (!closed) {
            bytes?.fill(0)
            bytes = null
            invocationId.fill(0)
            closed = true
        }
    }

    private fun activeBytes(): ByteArray = bytes
        ?: error("fixed content salt has not been bound to a reproducibility context")

    private companion object {
        const val SALT_SIZE = 32
    }
}

private class PerInvocationSecureEntropy : EntropySource {
    private val random = SecureRandom()

    override fun nextBytes(purpose: String, size: Int): ByteArray = ByteArray(size).also(random::nextBytes)
}
