package com.holin.android.hardening.artifact

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class OwnedApkBinaryXmlTargetSelectorTest {
    @Test
    fun `selects exact rewritten owned XML APK paths only`() {
        val manifest = manifest(
            BundleRewriteEntry.renamed(
                "base/res/layout/old_screen.xml",
                "base/res/layout/hardened_screen.xml",
                hash('1'),
            ),
            transformed(
                "base/res/drawable/vector.xml",
                "base/res/drawable/vector.xml",
                BundleSemanticVerifier.RESOURCE_SEMANTICS,
            ),
            transformed("base/resources.pb", "base/resources.pb", BundleSemanticVerifier.RESOURCE_SEMANTICS),
            transformed(
                "base/res/drawable/hero.png",
                "base/res/drawable/hardened_hero.png",
                BundleSemanticVerifier.RESOURCE_SEMANTICS,
            ),
            transformed("base/dex/classes.dex", "base/dex/classes.dex", BundleSemanticVerifier.DEX_SEMANTICS),
            transformed(
                "base/manifest/AndroidManifest.xml",
                "base/manifest/AndroidManifest.xml",
                BundleSemanticVerifier.RESOURCE_SEMANTICS,
            ),
            BundleRewriteEntry.preserved("base/res/layout/unowned.xml", hash('5')),
            BundleRewriteEntry.removed("BUNDLE-METADATA/com.holin.android.hardening/old.json", hash('6')),
            BundleRewriteEntry.renamed(
                "base/res/raw/plain_config.xml",
                "base/res/raw/sl_raw_plain_config.xml",
                hash('7'),
            ),
        )

        assertEquals(
            listOf("res/drawable/vector.xml", "res/layout/hardened_screen.xml"),
            OwnedApkBinaryXmlTargetSelector().select(manifest),
        )
    }

    @Test
    fun `selects an empty target set when the invocation owns no rewritten XML`() {
        val manifest = manifest(
            transformed("base/resources.pb", "base/resources.pb", BundleSemanticVerifier.RESOURCE_SEMANTICS),
            BundleRewriteEntry.preserved("base/res/layout/unowned.xml", hash('5')),
        )

        assertEquals(emptyList(), OwnedApkBinaryXmlTargetSelector().select(manifest))
    }

    @Test
    fun `rejects portable duplicate selected paths`() {
        val manifest = manifest(
            transformed(
                "base/res/layout/Screen.xml",
                "base/res/layout/Screen.xml",
                BundleSemanticVerifier.RESOURCE_SEMANTICS,
                oldHash = hash('1'),
                newHash = hash('2'),
            ),
            transformed(
                "base/res/layout/screen.xml",
                "base/res/layout/screen.xml",
                BundleSemanticVerifier.RESOURCE_SEMANTICS,
                oldHash = hash('3'),
                newHash = hash('4'),
            ),
        )

        assertFailsWith<IllegalArgumentException> {
            OwnedApkBinaryXmlTargetSelector().select(manifest)
        }
    }

    @Test
    fun `rewrite manifest rejects unsafe selected paths before mapping`() {
        assertFailsWith<IllegalArgumentException> {
            transformed(
                "base/res/layout/../unsafe.xml",
                "base/res/layout/unsafe.xml",
                BundleSemanticVerifier.RESOURCE_SEMANTICS,
            )
        }
    }

    @Test
    fun `target path digest is sorted deterministic and does not expose raw paths`() {
        val first = ApkBinaryXmlTargetPathDigest.sha256(
            listOf("res/layout/z.xml", "res/drawable/a.xml"),
        )
        val reordered = ApkBinaryXmlTargetPathDigest.sha256(
            listOf("res/drawable/a.xml", "res/layout/z.xml"),
        )

        assertEquals(first, reordered)
        assertEquals(64, first.length)
        assertFalse(first.contains("res/"))
    }

    @Test
    fun `target path digest accounts for an empty selected set`() {
        assertEquals(64, ApkBinaryXmlTargetPathDigest.sha256(emptyList()).length)
    }

    private fun transformed(
        oldPath: String,
        newPath: String,
        verifier: BundleSemanticVerifier,
        oldHash: String = hash('1'),
        newHash: String = hash('2'),
    ): BundleRewriteEntry = BundleRewriteEntry.transformed(oldPath, oldHash, newPath, newHash, verifier)

    private fun manifest(vararg entries: BundleRewriteEntry): BundleRewriteManifest = BundleRewriteManifest(
        originalAabSha256 = hash('a'),
        contentSaltSha256 = hash('b'),
        entries = entries.toList(),
    )

    private fun hash(character: Char): String = character.toString().repeat(64)
}
