package com.holin.android.hardening

import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.createSymbolicLinkPointingTo
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.gradle.testfixtures.ProjectBuilder
import org.junit.jupiter.api.io.TempDir

class HardeningOwnershipTest {
    @TempDir
    lateinit var projectDirectory: Path

    @Test
    fun `resolves declared source sets in declaration order`() {
        projectDirectory.resolve("src/main").createDirectories()
        projectDirectory.resolve("src/demo").createDirectories()
        val project = ProjectBuilder.builder().withProjectDir(projectDirectory.toFile()).build()

        val ownership = HardeningOwnership.resolve(
            project,
            linkedMapOf(":" to linkedSetOf("main", "demo")),
            linkedSetOf("com.example.generated"),
            linkedSetOf("com.example.excluded"),
        )

        assertEquals(listOf(":"), ownership.modules.map(HardeningOwnership.OwnedModule::path))
        assertEquals(linkedSetOf("main", "demo"), ownership.modules.single().sourceSets)
        assertEquals(0, ownership.priority(":"))
        assertEquals(
            linkedSetOf("Lcom/example/generated/", "Lcom/example/excluded/"),
            ownership.deniedDexDescriptorPrefixes,
        )
    }

    @Test
    fun `accepts production source sets whose names merely contain test`() {
        projectDirectory.resolve("src/contest").createDirectories()
        val project = ProjectBuilder.builder().withProjectDir(projectDirectory.toFile()).build()

        val ownership = HardeningOwnership.resolve(
            project,
            linkedMapOf(":" to linkedSetOf("contest")),
            emptySet(),
            emptySet(),
        )

        assertEquals(setOf("contest"), ownership.modules.single().sourceSets)
    }

    @Test
    fun `rejects generated and test source path variants without rejecting production names`() {
        val moduleDirectory = projectDirectory.resolve("app").createDirectories()
        listOf(
            "src/main/generated-res",
            "src/main/Generated_Res",
            "src/main/testFixtures",
            "src/main/androidTest-res",
            "build/generated/source",
            "src/main/unitTest",
            "src/main/integration-test",
            "src/main/build-output",
        ).forEach { relativePath ->
            assertFailsWith<IllegalArgumentException> {
                HardeningOwnership.validateProductionPath(
                    ":app",
                    moduleDirectory,
                    moduleDirectory.resolve(relativePath),
                )
            }
        }

        HardeningOwnership.validateProductionPath(
            ":app",
            moduleDirectory,
            moduleDirectory.resolve("src/main/contest/res"),
        )
        HardeningOwnership.validateProductionPath(
            ":app",
            moduleDirectory,
            moduleDirectory.resolve("src/main/testament/res"),
        )
    }

    @Test
    fun `rejects explicit manifest through a parent symlink outside the real module boundary`() {
        val moduleDirectory = projectDirectory.resolve("app").createDirectories()
        val outside = projectDirectory.resolve("outside").createDirectories()
        outside.resolve("AndroidManifest.xml").writeText("<manifest />")
        moduleDirectory.resolve("src").createDirectories()
        moduleDirectory.resolve("src/custom").createSymbolicLinkPointingTo(outside)

        val failure = assertFailsWith<IllegalArgumentException> {
            HardeningOwnership.validateProductionPath(
                ":app",
                moduleDirectory,
                moduleDirectory.resolve("src/custom/AndroidManifest.xml"),
            )
        }

        assertTrue(failure.message.orEmpty().contains("real module boundary"))
    }

    @Test
    fun `rejects unknown source sets and malformed package prefixes`() {
        projectDirectory.resolve("src/main").createDirectories()
        val project = ProjectBuilder.builder().withProjectDir(projectDirectory.toFile()).build()

        val missingSourceSet = assertFailsWith<IllegalArgumentException> {
            HardeningOwnership.resolve(project, linkedMapOf(":" to linkedSetOf("demo")), emptySet(), emptySet())
        }
        assertTrue(missingSourceSet.message.orEmpty().contains("source set directory"))

        val malformedPrefix = assertFailsWith<IllegalArgumentException> {
            HardeningOwnership.resolve(project, linkedMapOf(":" to linkedSetOf("main")), setOf("com..broken"), emptySet())
        }
        assertTrue(malformedPrefix.message.orEmpty().contains("malformed package prefix"))
    }

    @Test
    fun `rejects empty ownership declarations`() {
        val project = ProjectBuilder.builder().withProjectDir(projectDirectory.toFile()).build()

        val failure = assertFailsWith<IllegalArgumentException> {
            HardeningOwnership.resolve(project, emptyMap(), emptySet(), emptySet())
        }

        assertTrue(failure.message.orEmpty().contains("declare at least one module"))
    }

    @Test
    fun `rejects empty source set declarations`() {
        val project = ProjectBuilder.builder().withProjectDir(projectDirectory.toFile()).build()

        val failure = assertFailsWith<IllegalArgumentException> {
            HardeningOwnership.resolve(project, linkedMapOf(":" to emptySet()), emptySet(), emptySet())
        }

        assertTrue(failure.message.orEmpty().contains("must declare source sets"))
    }

    @Test
    fun `rejects unknown project paths`() {
        val project = ProjectBuilder.builder().withProjectDir(projectDirectory.toFile()).build()

        val failure = assertFailsWith<IllegalArgumentException> {
            HardeningOwnership.resolve(project, linkedMapOf(":missing" to linkedSetOf("main")), emptySet(), emptySet())
        }

        assertTrue(failure.message.orEmpty().contains("project does not exist"))
    }

    @Test
    fun `rejects duplicate module declarations in the DSL`() {
        val project = ProjectBuilder.builder().withProjectDir(projectDirectory.toFile()).build()
        val spec = project.objects.newInstance(OwnershipSpec::class.java, project.objects)

        spec.module(":") { sourceSets.add("main") }
        val failure = assertFailsWith<IllegalArgumentException> {
            spec.module(":") { sourceSets.add("demo") }
        }

        assertTrue(failure.message.orEmpty().contains("duplicate module declaration"))
    }

    @Test
    fun `preserves declaration order as module priority`() {
        projectDirectory.resolve("mobile/src/main").createDirectories()
        projectDirectory.resolve("core/src/shared").createDirectories()
        val root = ProjectBuilder.builder().withProjectDir(projectDirectory.toFile()).build()
        ProjectBuilder.builder().withParent(root).withName("mobile").withProjectDir(projectDirectory.resolve("mobile").toFile()).build()
        ProjectBuilder.builder().withParent(root).withName("core").withProjectDir(projectDirectory.resolve("core").toFile()).build()

        val ownership = HardeningOwnership.resolve(
            root,
            linkedMapOf(":core" to linkedSetOf("shared"), ":mobile" to linkedSetOf("main")),
            emptySet(),
            emptySet(),
        )

        assertEquals(listOf(":core", ":mobile"), ownership.modules.map(HardeningOwnership.OwnedModule::path))
        assertEquals(0, ownership.priority(":core"))
        assertEquals(1, ownership.priority(":mobile"))
    }

    @Test
    fun `rejects hierarchical generated and excluded package overlap`() {
        projectDirectory.resolve("src/main").createDirectories()
        val project = ProjectBuilder.builder().withProjectDir(projectDirectory.toFile()).build()

        val failure = assertFailsWith<IllegalArgumentException> {
            HardeningOwnership.resolve(
                project,
                linkedMapOf(":" to linkedSetOf("main")),
                linkedSetOf("com.example"),
                linkedSetOf("com.example.generated"),
            )
        }

        assertTrue(failure.message.orEmpty().contains("must not overlap"))

        val reverseFailure = assertFailsWith<IllegalArgumentException> {
            HardeningOwnership.resolve(
                project,
                linkedMapOf(":" to linkedSetOf("main")),
                linkedSetOf("com.example.generated"),
                linkedSetOf("com.example"),
            )
        }

        assertTrue(reverseFailure.message.orEmpty().contains("must not overlap"))
    }

    @Test
    fun `takes defensive immutable snapshots of ownership inputs`() {
        val sourceSets = linkedSetOf("main")
        val modules = mutableListOf(HardeningOwnership.OwnedModule(":", projectDirectory, sourceSets))
        val generated = linkedSetOf("com.example.generated")
        val excluded = linkedSetOf("com.example.excluded")

        val ownership = HardeningOwnership(modules, generated, excluded)
        modules.clear()
        sourceSets += "demo"
        generated += "com.example.generated.more"
        excluded += "com.example.excluded.more"

        assertEquals(listOf(":"), ownership.modules.map(HardeningOwnership.OwnedModule::path))
        assertEquals(setOf("main"), ownership.modules.single().sourceSets)
        assertEquals(setOf("com.example.generated"), ownership.generatedPackagePrefixes)
        assertEquals(setOf("com.example.excluded"), ownership.excludedPackagePrefixes)
        assertEquals(setOf(":"), ownership.modulePaths)
    }
}
