package com.holin.android.hardening.inventory

import com.holin.android.hardening.HardeningOwnership
import com.holin.android.hardening.testHardeningOwnership
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class AppSourceInventoryTest {
    @TempDir lateinit var repository: Path

    @Test
    fun `ownership modules arbitrary source sets and configured package exclusions drive inventory`() {
        gitInit()
        repository.resolve(".gitignore").writeText("mobile/src/common/java/ignored/\n")
        source("mobile/src/common/java/com/example/Foo.java")
        source("mobile/src/orchid/kotlin/com/example/Foo.kt")
        source("mobile/src/common/java/com/example/Only.java")
        source("mobile/src/common/java/ignored/Ignored.java")
        source("mobile/src/common/java/com/acme/generated/Junk.java")
        source("mobile/src/common/java/com/acme/excluded/Excluded.java")
        source("mobile/src/common/res/layout/card.xml")
        source("mobile/src/orchid/res/layout/card.xml")
        source("mobile/src/common/AndroidManifest.xml")
        source("mobile/src/orchid/AndroidManifest.xml")
        source("core/src/shared/java/com/example/Core.java")
        source("media/src/catalog/kotlin/com/example/Media.kt")
        val modules = linkedSetOf(":mobile", ":core", ":media")
        val ownership = testHardeningOwnership(
            repository,
            modules,
            linkedMapOf(
                ":mobile" to linkedSetOf("common", "orchid"),
                ":core" to linkedSetOf("shared"),
                ":media" to linkedSetOf("catalog"),
            ),
            setOf("com.acme.generated"),
            setOf("com.acme.excluded"),
        )

        val result = AppSourceInventory(repository, ownership, GitIgnoreMatcher(repository)).scan()
        val relative = result.map { repository.relativize(it.path).toString().replace('\\', '/') }.toSet()

        assertEquals(
            setOf(
                "mobile/src/orchid/kotlin/com/example/Foo.kt",
                "mobile/src/common/java/com/example/Only.java",
                "mobile/src/orchid/res/layout/card.xml",
                "mobile/src/common/AndroidManifest.xml",
                "mobile/src/orchid/AndroidManifest.xml",
                "core/src/shared/java/com/example/Core.java",
                "media/src/catalog/kotlin/com/example/Media.kt",
            ),
            relative,
        )
        assertEquals("orchid", result.single { it.logicalName == "com/example/Foo" }.sourceSet)
        assertEquals(modules, result.mapTo(linkedSetOf(), StaticAppSource::modulePath))
    }

    @Test
    fun `same ownership layer Java and Kotlin winners are ambiguous`() {
        gitInit()
        source("mobile/src/orchid/java/com/example/Duplicate.java")
        source("mobile/src/orchid/kotlin/com/example/Duplicate.kt")
        val ownership = testHardeningOwnership(
            repository,
            setOf(":mobile"),
            mapOf(":mobile" to setOf("orchid")),
            emptySet(),
            emptySet(),
        )

        val failure = assertFailsWith<AmbiguousAppSourceException> {
            AppSourceInventory(repository, ownership, GitIgnoreMatcher(repository)).scan()
        }

        assertTrue(failure.message.orEmpty().contains("com/example/Duplicate"))
    }

    @Test
    fun `same physical root exposed as Java and Kotlin is inventoried once`() {
        gitInit()
        val java = source("mobile/custom/production/com/example/OwnedJava.java")
        val kotlin = source("mobile/custom/production/com/example/OwnedKotlin.kt")
        val sourceRoot = repository.resolve("mobile/custom/production")
        val moduleDirectory = repository.resolve("mobile")
        val ownership = HardeningOwnership(
            listOf(
                HardeningOwnership.OwnedModule(
                    ":mobile",
                    moduleDirectory,
                    setOf("demo"),
                    HardeningOwnership.ResolvedSourceRoots.fromSourceSets(
                        listOf(
                            HardeningOwnership.ResolvedSourceSetRoots(
                                "demo",
                                setOf(sourceRoot),
                                setOf(sourceRoot),
                                emptySet(),
                                emptySet(),
                            ),
                        ),
                    ),
                ),
            ),
            emptySet(),
            emptySet(),
        )

        val result = AppSourceInventory(repository, ownership, GitIgnoreMatcher(repository)).scan()

        assertEquals(setOf(java, kotlin), result.mapTo(linkedSetOf(), StaticAppSource::path))
    }

    @Test
    fun `resolved source set origin includes nonconventional AGP source roots`() {
        gitInit()
        val commonJava = source("mobile/custom/common-code/com/example/Foo.java")
        val orchidJava = source("mobile/custom/orchid-code/com/example/Foo.java")
        val moduleDirectory = repository.resolve("mobile")
        val roots = HardeningOwnership.ResolvedSourceRoots.fromSourceSets(
            listOf(
                HardeningOwnership.ResolvedSourceSetRoots(
                    "common",
                    setOf(commonJava.parent.parent.parent),
                    emptySet(),
                    emptySet(),
                    emptySet(),
                ),
                HardeningOwnership.ResolvedSourceSetRoots(
                    "orchid",
                    setOf(orchidJava.parent.parent.parent),
                    emptySet(),
                    emptySet(),
                    emptySet(),
                ),
            ),
        )
        val ownership = HardeningOwnership(
            listOf(
                HardeningOwnership.OwnedModule(
                    ":mobile",
                    moduleDirectory,
                    linkedSetOf("common", "orchid"),
                    roots,
                ),
            ),
            emptySet(),
            emptySet(),
        )

        val result = AppSourceInventory(repository, ownership, GitIgnoreMatcher(repository)).scan()

        assertEquals(orchidJava, result.single().path)
        assertEquals("orchid", result.single().sourceSet)
    }

    private fun gitInit() {
        val process = ProcessBuilder("git", "init", "-q", repository.toString()).start()
        check(process.waitFor() == 0) { process.errorStream.bufferedReader().readText() }
    }

    private fun source(relative: String): Path = repository.resolve(relative).also { path ->
        path.parent?.createDirectories()
        path.writeText(relative)
    }
}
