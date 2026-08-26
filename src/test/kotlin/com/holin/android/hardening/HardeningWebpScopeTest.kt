package com.holin.android.hardening

import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class HardeningWebpScopeTest {
    @TempDir
    lateinit var moduleDirectory: Path

    @Test
    fun `normalizes module relative globs and applies exclude precedence case sensitively`() {
        val scope = HardeningOwnership.WebpScope.resolve(
            setOf("./src//main/res/drawable/**/*.webp", "src/main/res-im/*.webp"),
            setOf("src/main/res/drawable/private/**"),
        )

        assertEquals(
            setOf("src/main/res/drawable/**/*.webp", "src/main/res-im/*.webp"),
            scope.includes,
        )
        assertTrue(scope.includes("src/main/res/drawable/icons/hero.webp"))
        assertTrue(scope.includes("src/main/res-im/hero.webp"))
        assertFalse(scope.includes("src/main/res/drawable/private/hero.webp"))
        assertFalse(scope.includes("src/main/res/drawable/icons/HERO.WEBP"))
    }

    @Test
    fun `empty include scope is opt in and matches nothing`() {
        val scope = HardeningOwnership.WebpScope.resolve(emptySet(), emptySet())

        assertFalse(scope.includes("src/main/res/drawable/hero.webp"))
    }

    @Test
    fun `rejects unsafe blank and duplicate normalized globs`() {
        listOf("", "   ", "/src/main/res/**/*.webp", "C:/src/main/res/*.webp", "src\\main\\res\\*.webp", "src/../res/*.webp")
            .forEach { pattern ->
                assertFailsWith<IllegalArgumentException> {
                    HardeningOwnership.WebpScope.resolve(listOf(pattern), emptyList())
                }
            }

        val duplicate = assertFailsWith<IllegalArgumentException> {
            HardeningOwnership.WebpScope.resolve(
                listOf("src/main/res/*.webp", "./src//main/res/*.webp"),
                emptyList(),
            )
        }
        assertTrue(duplicate.message.orEmpty().contains("duplicate WebP include"))
    }

    @Test
    fun `owned module snapshots resolved production roots and webp scope immutably`() {
        val javaRoots = linkedSetOf(moduleDirectory.resolve("src/main/java"))
        val resourceRoots = linkedSetOf(moduleDirectory.resolve("src/main/res-im"))
        val includes = linkedSetOf("src/main/res-im/**/*.webp")
        val roots = HardeningOwnership.ResolvedSourceRoots(
            javaRoots,
            emptySet(),
            resourceRoots,
            setOf(moduleDirectory.resolve("src/main/AndroidManifest.xml")),
        )
        val module = HardeningOwnership.OwnedModule(
            ":selector",
            moduleDirectory,
            setOf("main"),
            roots,
            HardeningOwnership.WebpScope.resolve(includes, emptySet()),
        )

        javaRoots.add(moduleDirectory.resolve("src/demo/java"))
        resourceRoots.add(moduleDirectory.resolve("src/main/res"))
        includes.add("src/main/res/**/*.webp")

        assertEquals(setOf(moduleDirectory.resolve("src/main/java")), module.sourceRoots.javaDirectories)
        assertEquals(setOf(moduleDirectory.resolve("src/main/res-im")), module.sourceRoots.resourceDirectories)
        assertEquals(setOf("src/main/res-im/**/*.webp"), module.webp.includes)
    }
}
