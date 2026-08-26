package com.holin.android.hardening.state

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals

class InvocationSaltServiceTest {
    @Test
    fun `one invocation owns a stable 32 byte salt and sha256`() {
        val salt = InvocationSalt(SequenceEntropy(0x11))

        val first = salt.withSalt { it.copyOf() }
        val second = salt.withSalt { it.copyOf() }

        assertEquals(32, first.size)
        assertContentEquals(first, second)
        assertEquals(Sha256.hex(first), salt.sha256())
    }

    @Test
    fun `separate invocations rotate content salt`() {
        val first = InvocationSalt(SequenceEntropy(0x11))
        val second = InvocationSalt(SequenceEntropy(0x22))

        assertFalse(first.sha256() == second.sha256())
    }

    @Test
    fun `raw salt access is limited to the callback and close clears service state`() {
        val salt = InvocationSalt(SequenceEntropy(0x11))
        lateinit var retained: ByteArray

        salt.withSalt { retained = it }

        assertContentEquals(ByteArray(32), retained)
        salt.close()
        assertFailsWith<IllegalStateException> { salt.sha256() }
        assertFailsWith<IllegalStateException> { salt.withSalt { } }
    }

    @Test
    fun `fixed seed binds deterministic content and purpose separated lineage material`() {
        val seedHash = FixedSeedDerivation.seedSha256("fixture-fixed-seed")
        val context = ReproducibilityContext("demo", "demoRelease", "a".repeat(64))
        val first = InvocationSalt(SequenceEntropy(0x11), seedHash)
        val second = InvocationSalt(SequenceEntropy(0x22), seedHash)

        first.bind(context)
        second.bind(context)

        assertEquals(first.sha256(), second.sha256())
        assertContentEquals(first.withSalt(ByteArray::copyOf), second.withSalt(ByteArray::copyOf))
        assertEquals(first.stateReproducibility().lineageId, second.stateReproducibility().lineageId)
        assertFalse(
            first.withSalt(ByteArray::copyOf)
                .contentEquals(first.stateReproducibility().newLineageSeed()),
        )
        assertNotEquals(first.invocationIdSha256(), second.invocationIdSha256())
    }

    @Test
    fun `fixed seed rejects use before binding and a second different context`() {
        val seedHash = FixedSeedDerivation.seedSha256("fixture-fixed-seed")
        val salt = InvocationSalt(SequenceEntropy(0x11), seedHash)
        val first = ReproducibilityContext("demo", "demoRelease", "a".repeat(64))
        val second = ReproducibilityContext("demo", "demoDebug", "a".repeat(64))

        assertFailsWith<IllegalStateException> { salt.sha256() }
        salt.bind(first)
        assertFailsWith<IllegalStateException> { salt.bind(second) }
    }

    private class SequenceEntropy(private val value: Int) : EntropySource {
        override fun nextBytes(purpose: String, size: Int): ByteArray = ByteArray(size) { value.toByte() }
    }
}
