package com.holin.android.hardening

import com.holin.android.hardening.state.Sha256
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import org.gradle.testfixtures.ProjectBuilder

class OwnedSimilarityConfigurationIdentityTest {
    @Test
    fun `configuration identity contains fixed seed presence and hash but never raw text`() {
        val extension = extension()
        val rawSeed = "raw-fixture-seed-must-not-leak"
        extension.reproducibility.fixedSeed.set(rawSeed)

        val canonical = canonicalIdentity(extension)

        assertTrue("reproducibility.fixedSeedPresent=true" in canonical)
        assertTrue(Sha256.hex(rawSeed.toByteArray(Charsets.UTF_8)) in canonical)
        assertFalse(rawSeed in canonical)
    }

    @Test
    fun `changing an artifact transform setting changes baseline configuration identity`() {
        val project = ProjectBuilder.builder().build()
        val extension = project.objects.newInstance(
            AndroidHardeningExtension::class.java,
            project.objects,
            project.layout,
        )
        extension.projectKey.set("demo")
        extension.variants.include("demoDebug")
        val original = OwnedSimilarityConfigurationIdentity.sha256(
            extension,
            variant = "demoDebug",
            namespace = "com.example.demo.match",
            applicationId = "com.example.demo.match",
            versionCode = 1,
            versionName = "1.0.0",
            signingCertificateSha256 = "a".repeat(64),
            legacyPlugins = listOf(legacyPlugin()),
            legacyBaselineSha256 = "c".repeat(64),
        )

        extension.code.diversification.minimumSimHashDistance.set(5)

        assertNotEquals(
            original,
            OwnedSimilarityConfigurationIdentity.sha256(
                extension,
                variant = "demoDebug",
                namespace = "com.example.demo.match",
                applicationId = "com.example.demo.match",
                versionCode = 1,
                versionName = "1.0.0",
                signingCertificateSha256 = "a".repeat(64),
                legacyPlugins = listOf(legacyPlugin()),
                legacyBaselineSha256 = "c".repeat(64),
            ),
        )
    }

    @Test
    fun `version name and signing certificate each change baseline configuration identity`() {
        val extension = extension()
        val original = identity(extension)

        assertNotEquals(original, identity(extension, versionName = "1.0.1"))
        assertNotEquals(original, identity(extension, signingCertificateSha256 = "b".repeat(64)))
    }

    @Test
    fun `legacy plugin version changes baseline configuration identity`() {
        val extension = extension()
        val original = identity(extension)

        assertNotEquals(
            original,
            identity(
                extension,
                legacyPlugins = listOf(legacyPlugin("9.9.9")),
            ),
        )
    }

    @Test
    fun `legacy plugin configuration and mapping paths change baseline configuration identity`() {
        val extension = extension()
        val original = identity(extension)

        assertNotEquals(
            original,
            identity(
                extension,
                legacyPlugins = listOf(legacyPlugin(configurationInputs = listOf("config/changed.gradle.kts"))),
            ),
        )
        assertNotEquals(
            original,
            identity(
                extension,
                legacyPlugins = listOf(legacyPlugin(mappingPaths = listOf("mapping/changed.txt"))),
            ),
        )
    }

    @Test
    fun `legacy plugin baseline content changes baseline configuration identity`() {
        val extension = extension()

        assertNotEquals(
            identity(extension),
            identity(extension, legacyBaselineSha256 = "d".repeat(64)),
        )
    }

    @Test
    fun `resolved source roots and WebP scope change baseline configuration identity`() {
        val extension = extension()
        val first = ownership("src/main/res", "src/main/res/**/*.webp", emptySet())
        val changedRoot = ownership("src/main/res-im", "src/main/res/**/*.webp", emptySet())
        val changedInclude = ownership("src/main/res", "src/main/res/icons/*.webp", emptySet())
        val changedExclude = ownership("src/main/res", "src/main/res/**/*.webp", setOf("src/main/res/private/**"))

        assertNotEquals(identity(extension, ownership = first), identity(extension, ownership = changedRoot))
        assertNotEquals(identity(extension, ownership = first), identity(extension, ownership = changedInclude))
        assertNotEquals(identity(extension, ownership = first), identity(extension, ownership = changedExclude))
    }

    @Test
    fun `resolved custom manifest file changes baseline configuration identity`() {
        val extension = extension()
        val conventional = ownership("src/main/res", "src/main/res/**/*.webp", emptySet())
        val customManifest = ownership(
            "src/main/res",
            "src/main/res/**/*.webp",
            emptySet(),
            "src/owned-manifest/AndroidManifest.xml",
        )

        assertNotEquals(identity(extension, ownership = conventional), identity(extension, ownership = customManifest))
    }

    @Test
    fun `effective hardcoded reference scope changes baseline configuration identity`() {
        val extension = extension()
        val defaultScope = HardeningOwnership.HardcodedReferenceScope.defaults()
        val narrowedScope = HardeningOwnership.HardcodedReferenceScope.resolve(
            setOf(HardcodedReferenceKind.URL),
            setOf("src/main/kotlin/**/*.kt"),
            setOf("**/test/**"),
            false,
            true,
        )

        assertNotEquals(
            identityWithOwnership(extension, ownership("src/main/res", "src/main/res/**/*.webp", emptySet(), "src/main/AndroidManifest.xml", defaultScope)),
            identityWithOwnership(extension, ownership("src/main/res", "src/main/res/**/*.webp", emptySet(), "src/main/AndroidManifest.xml", narrowedScope)),
        )
    }

    @Test
    fun `signing certificate identity must be strict lowercase SHA-256`() {
        val extension = extension()

        listOf("a".repeat(63), "A".repeat(64), "g".repeat(64)).forEach { digest ->
            val failure = assertFailsWith<IllegalArgumentException> {
                identity(extension, signingCertificateSha256 = digest)
            }
            assertTrue(failure.message.orEmpty().contains("lowercase SHA-256"))
        }
    }

    private fun extension(): AndroidHardeningExtension {
        val project = ProjectBuilder.builder().build()
        return project.objects.newInstance(
            AndroidHardeningExtension::class.java,
            project.objects,
            project.layout,
        ).also { extension ->
            extension.projectKey.set("demo")
            extension.variants.include("demoDebug")
        }
    }

    private fun identity(
        extension: AndroidHardeningExtension,
        versionName: String = "1.0.0",
        signingCertificateSha256: String = "a".repeat(64),
        legacyPlugins: List<LegacyPluginDeclaration> = listOf(legacyPlugin()),
        legacyBaselineSha256: String = "c".repeat(64),
        ownership: HardeningOwnership? = null,
    ): String = OwnedSimilarityConfigurationIdentity.sha256(
        extension,
        "demoDebug",
        "com.example.demo.match",
        "com.example.demo.match",
        1,
        versionName,
        signingCertificateSha256,
        ownership,
        legacyPlugins,
        legacyBaselineSha256,
    )

    private fun canonicalIdentity(extension: AndroidHardeningExtension): String =
        OwnedSimilarityConfigurationIdentity.canonicalText(
            extension,
            "demoDebug",
            "com.example.demo.match",
            "com.example.demo.match",
            1,
            "1.0.0",
            "a".repeat(64),
            null,
            listOf(legacyPlugin()),
            "c".repeat(64),
        )

    private fun identityWithOwnership(
        extension: AndroidHardeningExtension,
        ownership: HardeningOwnership,
    ): String = identity(
        extension,
        "1.0.0",
        "a".repeat(64),
        listOf(legacyPlugin()),
        "c".repeat(64),
        ownership,
    )

    private fun ownership(
        resourceRoot: String,
        include: String,
        excludes: Set<String>,
        manifestPath: String = "src/main/AndroidManifest.xml",
        hardcodedScope: HardeningOwnership.HardcodedReferenceScope = HardeningOwnership.HardcodedReferenceScope.defaults(),
    ): HardeningOwnership {
        val module = Path.of("/repository/app")
        val roots = HardeningOwnership.ResolvedSourceRoots(
            setOf(module.resolve("src/main/java")),
            setOf(module.resolve("src/main/kotlin")),
            setOf(module.resolve(resourceRoot)),
            setOf(module.resolve(manifestPath)),
        )
        return HardeningOwnership(
            listOf(
                HardeningOwnership.OwnedModule(
                    ":app",
                    module,
                    setOf("main"),
                    roots,
                    HardeningOwnership.WebpScope.resolve(setOf(include), excludes),
                ),
            ),
            emptySet(),
            emptySet(),
            hardcodedScope,
        )
    }

    private fun legacyPlugin(
        expectedVersion: String = "1.2.3",
        configurationInputs: List<String> = listOf("app/build.gradle.kts"),
        mappingPaths: List<String> = listOf("app/mapping.txt"),
    ) = LegacyPluginDeclaration(
        "fixture",
        "example.legacy.plugin",
        expectedVersion,
        configurationInputs,
        mappingPaths,
    )
}
