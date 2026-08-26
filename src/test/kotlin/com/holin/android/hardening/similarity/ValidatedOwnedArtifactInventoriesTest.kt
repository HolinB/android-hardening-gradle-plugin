package com.holin.android.hardening.similarity

import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class ValidatedOwnedArtifactInventoriesTest {
    @Test
    fun `identity hash stays immutable while analysis uses changed hardened locations`() {
        val identity = inventory()
        val changedLocation = OwnedResourceLocation(
            "changed.xml",
            "base/res/layout/changed.xml",
            "res/layout/changed.xml",
            HASH,
        )
        val analysis = identity.copy(hardenedOwnedResources = mapOf(KEY to changedLocation))

        val inventories = ValidatedOwnedArtifactInventories(identity, analysis)
        val request = inventories.analysisRequest(
            Path.of("ordinary.aab"),
            Path.of("hardened.aab"),
            Path.of("ordinary.apk"),
            Path.of("hardened.apk"),
        )

        assertNotEquals(identity.ownershipSha256, analysis.ownershipSha256)
        assertEquals(identity.ownershipSha256, inventories.identityOwnershipSha256)
        assertEquals(changedLocation, request.hardenedOwnedResources.getValue(KEY))
        assertEquals(analysis.ownedDescriptors, request.ownedDescriptors)
    }

    @Test
    fun `analysis inventory rejects changed owned modules`() {
        val identity = inventory()
        val analysis = identity.copy(setOf(":mobile"))

        val failure = assertFailsWith<IllegalArgumentException> {
            ValidatedOwnedArtifactInventories(identity, analysis)
        }

        assertTrue(failure.message.orEmpty().contains("identical"))
    }

    @Test
    fun `analysis inventory rejects changed owned descriptors`() {
        val identity = inventory()
        val analysis = identity.copy(ownedDescriptors = setOf("Lother/Owned;"))

        val failure = assertFailsWith<IllegalArgumentException> {
            ValidatedOwnedArtifactInventories(identity, analysis)
        }

        assertTrue(failure.message.orEmpty().contains("descriptors"))
    }

    @Test
    fun `analysis inventory rejects changed ordinary resource keys`() {
        val identity = inventory()
        val changedKey = OwnedResourceKey(2, "")
        val analysis = identity.copy(
            ordinaryOwnedResources = mapOf(changedKey to ORDINARY),
            hardenedOwnedResources = mapOf(changedKey to HARDENED),
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            ValidatedOwnedArtifactInventories(identity, analysis)
        }

        assertTrue(failure.message.orEmpty().contains("ordinary resource keys"))
    }

    @Test
    fun `analysis inventory rejects changed ordinary resource locations`() {
        val identity = inventory()
        val changed = ORDINARY.copy(
            entryName = "changed.xml",
            aabPath = "base/res/layout/changed.xml",
            apkPath = "res/layout/changed.xml",
        )
        val analysis = identity.copy(ordinaryOwnedResources = mapOf(KEY to changed))

        val failure = assertFailsWith<IllegalArgumentException> {
            ValidatedOwnedArtifactInventories(identity, analysis)
        }

        assertTrue(failure.message.orEmpty().contains("ordinary resource locations"))
    }

    @Test
    fun `analysis inventory rejects changed hardened resource keys`() {
        val changedKey = OwnedResourceKey(2, "")

        val failure = assertFailsWith<IllegalArgumentException> {
            inventory().copy(hardenedOwnedResources = mapOf(changedKey to HARDENED))
        }

        assertTrue(failure.message.orEmpty().contains("keys"))
    }

    @Test
    fun `analysis inventory rejects changed ordinary semantic hashes`() {
        val identity = inventory()
        val changedOrdinary = ORDINARY.copy(semanticHash = OTHER_HASH)
        val changedHardened = HARDENED.copy(semanticHash = OTHER_HASH)
        val analysis = identity.copy(
            ordinaryOwnedResources = mapOf(KEY to changedOrdinary),
            hardenedOwnedResources = mapOf(KEY to changedHardened),
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            ValidatedOwnedArtifactInventories(identity, analysis)
        }

        assertTrue(failure.message.orEmpty().contains("ordinary resource semantic hash"))
    }

    @Test
    fun `analysis inventory rejects changed hardened semantic hashes`() {
        val failure = assertFailsWith<IllegalArgumentException> {
            inventory().copy(hardenedOwnedResources = mapOf(KEY to HARDENED.copy(semanticHash = OTHER_HASH)))
        }

        assertTrue(failure.message.orEmpty().contains("semantic hash"))
    }

    private fun inventory() = OwnedArtifactInventory(
        ownedModules = linkedSetOf(":app", ":core", ":compress", ":selector", ":ucrop"),
        ownedDescriptors = setOf("Lowned/Type;"),
        ordinaryOwnedResources = mapOf(KEY to ORDINARY),
        hardenedOwnedResources = mapOf(KEY to HARDENED),
    )

    private companion object {
        val KEY = OwnedResourceKey(1, "")
        const val HASH = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        const val OTHER_HASH = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        val ORDINARY = OwnedResourceLocation(
            "home.xml",
            "base/res/layout/home.xml",
            "res/layout/home.xml",
            HASH,
        )
        val HARDENED = OwnedResourceLocation(
            "screen.xml",
            "base/res/layout/screen.xml",
            "res/layout/screen.xml",
            HASH,
        )
    }
}
