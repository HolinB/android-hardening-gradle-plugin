package com.holin.android.hardening.similarity

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class OwnedArtifactInventoryCodecTest {
    @Test
    fun `compiled inventory is deterministic strict and hashes exact ownership inputs`() {
        val inventory = inventory()

        val encoded = OwnedArtifactInventoryCodec.encode(inventory)

        assertEquals(encoded, OwnedArtifactInventoryCodec.encode(inventory))
        assertEquals(inventory, OwnedArtifactInventoryCodec.decode(encoded))
        assertEquals(64, inventory.ownershipSha256.length)
        assertFailsWith<IllegalArgumentException> {
            OwnedArtifactInventoryCodec.decode(encoded.replaceFirst("{", "{\"unexpected\":true,"))
        }
    }

    @Test
    fun `compiled inventory accepts arbitrary ownership and rejects an empty scope`() {
        val portable = inventory().copy(setOf(":mobile", ":core"))

        assertEquals(setOf(":mobile", ":core"), portable.ownedModules)
        val failure = assertFailsWith<IllegalArgumentException> {
            inventory().copy(emptySet())
        }

        assertTrue(failure.message.orEmpty().contains("must not be empty"))
    }

    private fun inventory() = OwnedArtifactInventory(
        ownedModules = linkedSetOf(":app", ":core", ":compress", ":selector", ":ucrop"),
        ownedDescriptors = linkedSetOf("La/b;", "Lc/d;"),
        ordinaryOwnedResources = linkedMapOf(
            OwnedResourceKey(1, "") to OwnedResourceLocation(
                "home.xml", "base/res/layout/home.xml", "res/layout/home.xml", "a".repeat(64),
            ),
        ),
        hardenedOwnedResources = linkedMapOf(
            OwnedResourceKey(1, "") to OwnedResourceLocation(
                "screen.xml", "base/res/layout/screen.xml", "res/layout/screen.xml", "a".repeat(64),
            ),
        ),
    )
}
