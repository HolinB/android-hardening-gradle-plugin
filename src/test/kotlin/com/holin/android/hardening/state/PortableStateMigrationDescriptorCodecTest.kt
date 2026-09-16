package com.holin.android.hardening.state

import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class PortableStateMigrationDescriptorCodecTest {
    @Test
    fun `descriptor encoding is deterministic and round trips every identity`() {
        val descriptor = descriptor()

        val encoded = PortableStateMigrationDescriptorCodec.encode(descriptor)

        assertEquals(descriptor, PortableStateMigrationDescriptorCodec.decode(encoded))
        assertEquals(encoded, PortableStateMigrationDescriptorCodec.encode(descriptor))
    }

    @Test
    fun `descriptor rejects unknown fields`() {
        val encoded = PortableStateMigrationDescriptorCodec.encode(descriptor())

        assertFailsWith<IllegalArgumentException> {
            PortableStateMigrationDescriptorCodec.decode(encoded.replaceFirst("{", "{\"unexpected\":true,"))
        }
    }

    @Test
    fun `descriptor supports state migration when no legacy baseline exists`() {
        val descriptor = descriptor(null)

        val encoded = PortableStateMigrationDescriptorCodec.encode(descriptor)

        assertContains(encoded, "\"baseline\":null")
        assertEquals(descriptor, PortableStateMigrationDescriptorCodec.decode(encoded))
    }

    @Test
    fun `descriptor supports constrained configuration migration within current content domain`() {
        val descriptor = descriptor(null, CanonicalContentDomain.HOLIN_1_2.id)

        val encoded = PortableStateMigrationDescriptorCodec.encode(descriptor)

        assertEquals(descriptor, PortableStateMigrationDescriptorCodec.decode(encoded))
    }

    private fun descriptor(
        baseline: PortableBaselineIdentityMigration? = PortableBaselineIdentityMigration(
            "owned-artifact-v1",
            "1".repeat(64),
            "2".repeat(64),
            "3".repeat(64),
            "4".repeat(64),
        ),
        fromContentDomain: String = CanonicalContentDomain.LEGACY_V1.id,
    ) = PortableStateMigrationDescriptor(
        2,
        "portable",
        "demoQa",
        PortableStateIdentityMigration(
            "com.example.portable",
            "com.example.portable.qa",
            fromContentDomain,
            CanonicalContentDomain.HOLIN_1_3.id,
            "a".repeat(64),
            "b".repeat(64),
            "11111111-2222-3333-4444-555555555555",
            7,
            "c".repeat(64),
            "d".repeat(64),
            "e".repeat(64),
            "f".repeat(64),
        ),
        baseline,
    )
}
