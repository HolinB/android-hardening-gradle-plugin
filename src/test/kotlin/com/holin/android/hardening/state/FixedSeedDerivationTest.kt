package com.holin.android.hardening.state

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class FixedSeedDerivationTest {
    private val context = ReproducibilityContext(
        "demo",
        "demoRelease",
        "a".repeat(64),
    )

    @Test
    fun `fixed seed hash is deterministic and rejects blank raw values`() {
        val first = FixedSeedDerivation.seedSha256("fixture-seed")
        val second = FixedSeedDerivation.seedSha256("fixture-seed")

        assertEquals(first, second)
        assertEquals(64, first.length)
        assertFailsWith<IllegalArgumentException> { FixedSeedDerivation.seedSha256(" \n") }
    }

    @Test
    fun `purpose separated values are stable and exactly 32 bytes`() {
        val seedHash = FixedSeedDerivation.seedSha256("fixture-seed")
        val content = FixedSeedDerivation.derive(seedHash, context, ReproducibilityPurpose.CONTENT_SALT)
        val naming = FixedSeedDerivation.derive(seedHash, context, ReproducibilityPurpose.NEW_LINEAGE_NAMING_SEED)
        val lineage = FixedSeedDerivation.derive(seedHash, context, ReproducibilityPurpose.NEW_LINEAGE_IDENTITY)

        assertEquals(32, content.size)
        assertEquals(32, naming.size)
        assertEquals(32, lineage.size)
        assertContentEquals(
            content,
            FixedSeedDerivation.derive(seedHash, context, ReproducibilityPurpose.CONTENT_SALT),
        )
        assertFalse(content.contentEquals(naming))
        assertFalse(content.contentEquals(lineage))
        assertFalse(naming.contentEquals(lineage))
    }

    @Test
    fun `seed configuration and variant each change every derived domain`() {
        val firstSeed = FixedSeedDerivation.seedSha256("fixture-seed-a")
        val secondSeed = FixedSeedDerivation.seedSha256("fixture-seed-b")
        val changedConfiguration = ReproducibilityContext("demo", "demoRelease", "b".repeat(64))
        val changedVariant = ReproducibilityContext("demo", "demoDebug", "a".repeat(64))

        ReproducibilityPurpose.values().forEach { purpose ->
            val original = FixedSeedDerivation.derive(firstSeed, context, purpose)
            assertFalse(original.contentEquals(FixedSeedDerivation.derive(secondSeed, context, purpose)))
            assertFalse(original.contentEquals(FixedSeedDerivation.derive(firstSeed, changedConfiguration, purpose)))
            assertFalse(original.contentEquals(FixedSeedDerivation.derive(firstSeed, changedVariant, purpose)))
        }
    }
}
