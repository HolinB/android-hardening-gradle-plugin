package com.holin.android.hardening

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import java.util.concurrent.atomic.AtomicInteger
import org.gradle.testfixtures.ProjectBuilder

class AndroidHardeningExtensionTest {
    @Test
    fun `ownership DSL retains declared modules source sets and package policies`() {
        val project = ProjectBuilder.builder().build()
        val extension = project.objects.newInstance(
            AndroidHardeningExtension::class.java,
            project.objects,
            project.layout,
        )

        extension.ownership {
            module(":shell") { sourceSets.add("main") }
            module(":feature:payments") { sourceSets.add("main") }
            generatedPackagePrefixes.add("com.example.generated")
            excludedPackagePrefixes.add("com.example.legacy")
        }

        assertEquals(
            linkedMapOf(
                ":shell" to setOf("main"),
                ":feature:payments" to setOf("main"),
            ),
            extension.ownership.modules.get(),
        )
        assertEquals(setOf("com.example.generated"), extension.ownership.generatedPackagePrefixes.get())
        assertEquals(setOf("com.example.legacy"), extension.ownership.excludedPackagePrefixes.get())
    }

    @Test
    fun `approved defaults are provider backed and complete`() {
        val project = ProjectBuilder.builder().build()
        val extension = project.objects.newInstance(
            AndroidHardeningExtension::class.java,
            project.objects,
            project.layout,
        )

        assertFalse(extension.enabled.get())
        assertTrue(extension.variants.included.get().isEmpty())
        assertTrue(extension.rules.sourceFiles.files.isEmpty())
        assertTrue(extension.rules.preserveExactRules.files.isEmpty())
        assertTrue(extension.rules.additionalRules.files.isEmpty())
        assertTrue(extension.mapping.reusePrevious.get())
        assertEquals(MissingPolicy.RECREATE, extension.mapping.missingPolicy.get())
        assertTrue(extension.mapping.keepHistory.get())
        assertTrue(extension.mapping.quarantineInvalid.get())
        assertEquals(60, extension.mapping.lockTimeoutSeconds.get())
        assertEquals(NamingStrategy.TYPED_PSEUDOWORDS, extension.naming.strategy.get())
        assertTrue(extension.naming.renamePackages.get())
        assertTrue(extension.naming.reuseAcrossBuilds.get())
        assertEquals(CodeEngine.R8, extension.code.engine.get())
        assertTrue(extension.code.preserveLineNumbers.get())
        assertEquals(SourceFileMode.PSEUDONYMIZE, extension.code.sourceFileMode.get())
        assertEquals(StringFogMode.PRESERVE_CURRENT, extension.code.stringFog.get())
        assertEquals(DiversificationMode.DEX, extension.code.diversification.mode.get())
        assertEquals(ContentSaltMode.FRESH_PER_BUILD, extension.code.diversification.contentSalt.get())
        assertEquals(0.50, extension.code.diversification.minimumCoverage.get())
        assertEquals(4, extension.code.diversification.minimumSimHashDistance.get())
        assertEquals(0.05, extension.code.diversification.maximumGrowth.get())
        assertFalse(extension.code.diversification.enforceMaximumGrowth.get())
        assertEquals(ResourceMode.RENAME_AND_AUDIT, extension.resources.mode.get())
        assertTrue(extension.resources.renameLayouts.get())
        assertTrue(extension.resources.renameDrawables.get())
        assertTrue(extension.resources.renameStyles.get())
        assertTrue(extension.resources.preserveResourceIds.get())
        assertTrue(extension.resources.reuseNamesAcrossBuilds.get())
        assertEquals(StyleHashPolicy.RESOURCE_TABLE_ONLY, extension.resources.styleHashPolicy.get())
        assertTrue(extension.resources.bitmapDiversification.safeOnly.get())
        assertEquals(0.90, extension.resources.bitmapDiversification.minimumCoverage.get())
        assertEquals(11, extension.resources.bitmapDiversification.minimumPHashDistance.get())
        assertEquals(0.995, extension.resources.bitmapDiversification.minimumSsim.get())
        assertEquals(UnresolvedContractPolicy.FAIL_BUILD, extension.contracts.unresolvedAppReflection.get())
        assertEquals(UnresolvedContractPolicy.FAIL_BUILD, extension.contracts.unresolvedResourceLookup.get())
        assertEquals(ExternalNamesMode.PRESERVE_AND_REPORT, extension.contracts.externalNames.get())
        assertTrue(extension.signing.reuseVariantSigningConfig.get())
        assertEquals(SimilarityMode.OWNED_AAB_APK, extension.similarity.mode.get())
        assertEquals(
            project.layout.projectDirectory.dir(".hardening/baselines").asFile,
            extension.similarity.baselineDirectory.get().asFile,
        )
        assertEquals(0.01, extension.similarity.minimumImprovementPoints.get())
        assertTrue(extension.similarity.enforceRelativeImprovement.get())
        assertFalse(extension.similarity.enforceMaximumOverall.get())
        assertFalse(extension.similarity.enforceMaximumAabGrowth.get())
        assertFalse(extension.deviceAcceptance.serial.isPresent)
        assertTrue(extension.deviceAcceptance.autoSelectSingleDevice.get())
        assertFalse(extension.deviceAcceptance.applicationId.isPresent)
        assertTrue(extension.deviceAcceptance.applicationIdFromVariant.get())
        assertFalse(extension.deviceAcceptance.launchActivity.isPresent)
        assertTrue(extension.deviceAcceptance.launchActivityFromManifest.get())
        assertEquals(30, extension.deviceAcceptance.stabilitySeconds.get())
        assertEquals(BenchmarkMode.REPORT_ONLY, extension.benchmark.mode.get())
        assertEquals(LegacyPluginMode.PRESERVE_UNMANAGED, extension.legacyPlugins.mode.get())
        assertTrue(extension.legacyPlugins.verifyCompatibility.get())
        assertFalse(extension.compatibility.autoMigrateLegacyState.get())
        assertFalse(extension.compatibility.migrationDescriptor.isPresent)
        assertFalse(extension.reproducibility.fixedSeed.isPresent)
    }

    @Test
    fun `reproducibility fixed seed remains provider backed`() {
        val project = ProjectBuilder.builder().build()
        val extension = project.objects.newInstance(
            AndroidHardeningExtension::class.java,
            project.objects,
            project.layout,
        )
        val queries = AtomicInteger()
        val seed = project.providers.provider {
            queries.incrementAndGet()
            "fixture-fixed-seed"
        }

        extension.reproducibility { fixedSeed.set(seed) }

        assertEquals(0, queries.get())
        assertEquals("fixture-fixed-seed", extension.reproducibility.fixedSeed.get())
        assertEquals(1, queries.get())
    }

    @Test
    fun `blank fixed seed is rejected during validation`() {
        val project = ProjectBuilder.builder().build()
        val extension = project.objects.newInstance(
            AndroidHardeningExtension::class.java,
            project.objects,
            project.layout,
        )
        extension.projectKey.set("demo")
        extension.variants.include("demoRelease")
        extension.reproducibility.fixedSeed.set(" \t")

        val failure = assertFailsWith<IllegalArgumentException> { extension.validateV1() }

        assertTrue(failure.message.orEmpty().contains("reproducibility.fixedSeed"))
    }

    @Test
    fun `nested Action helpers configure every level`() {
        val project = ProjectBuilder.builder().build()
        val extension = project.objects.newInstance(
            AndroidHardeningExtension::class.java,
            project.objects,
            project.layout,
        )

        extension.variants { include("demoRelease") }
        extension.rules {
            sourceFiles.from(project.file("portable-rules.pro"))
            preserveExactRules.from(project.file("preserved-rules.pro"))
            additionalRules.from(project.file("additional-rules.pro"))
        }
        extension.mapping { lockTimeoutSeconds.set(7) }
        extension.reproducibility { fixedSeed.set("fixture-fixed-seed") }
        extension.naming { renamePackages.set(false) }
        extension.code { diversification { minimumCoverage.set(0.75) } }
        extension.resources { bitmapDiversification { minimumSsim.set(0.999) } }
        extension.contracts { externalNames.set(ExternalNamesMode.PRESERVE_AND_REPORT) }
        extension.signing { reuseVariantSigningConfig.set(false) }
        extension.similarity {
            minimumImprovementPoints.set(0.02)
        }
        extension.deviceAcceptance {
            serial.set("test-device")
        }
        extension.benchmark { mode.set(BenchmarkMode.REPORT_ONLY) }
        extension.legacyPlugins { verifyCompatibility.set(false) }
        extension.compatibility {
            autoMigrateLegacyState.set(true)
            migrationDescriptor.set(project.layout.projectDirectory.file("hardening/migration.json"))
        }

        assertEquals(setOf("demoRelease"), extension.variants.included.get())
        assertEquals(setOf("portable-rules.pro"), extension.rules.sourceFiles.files.map { it.name }.toSet())
        assertEquals(setOf("preserved-rules.pro"), extension.rules.preserveExactRules.files.map { it.name }.toSet())
        assertEquals(setOf("additional-rules.pro"), extension.rules.additionalRules.files.map { it.name }.toSet())
        assertEquals(7, extension.mapping.lockTimeoutSeconds.get())
        assertEquals("fixture-fixed-seed", extension.reproducibility.fixedSeed.get())
        assertFalse(extension.naming.renamePackages.get())
        assertEquals(0.75, extension.code.diversification.minimumCoverage.get())
        assertEquals(0.999, extension.resources.bitmapDiversification.minimumSsim.get())
        assertFalse(extension.signing.reuseVariantSigningConfig.get())
        assertEquals(0.02, extension.similarity.minimumImprovementPoints.get())
        assertEquals("test-device", extension.deviceAcceptance.serial.get())
        assertFalse(extension.legacyPlugins.verifyCompatibility.get())
        assertTrue(extension.compatibility.autoMigrateLegacyState.get())
        assertEquals("migration.json", extension.compatibility.migrationDescriptor.get().asFile.name)
    }

    @Test
    fun `legacy plugin declarations resolve to immutable portable paths`() {
        val project = ProjectBuilder.builder().build()
        val extension = project.objects.newInstance(
            AndroidHardeningExtension::class.java,
            project.objects,
            project.layout,
        )
        val configuration = project.file("legacy/example.gradle.kts").apply {
            parentFile.mkdirs()
            writeText("plugins {}\n")
        }

        extension.legacyPlugins {
            baselineFile.set(project.layout.projectDirectory.file("legacy/baseline.json"))
            plugin("examplePlugin") {
                pluginId.set("com.example.legacy")
                expectedVersion.set("1.2.3")
                configurationInputs.from(configuration)
                mappingPaths.from(project.file("missing/example-mapping.txt"))
            }
        }

        val resolved = extension.legacyPlugins.resolve(project.rootProject).single()

        assertEquals("examplePlugin", resolved.name)
        assertEquals("com.example.legacy", resolved.pluginId)
        assertEquals("1.2.3", resolved.expectedVersion)
        assertEquals(listOf("legacy/example.gradle.kts"), resolved.configurationInputs)
        assertEquals(listOf("missing/example-mapping.txt"), resolved.mappingPaths)
        assertFailsWith<UnsupportedOperationException> {
            (resolved.configurationInputs as MutableList<String>).add("changed")
        }
    }

    @Test
    fun `range and v1 invariant validation is deferred until explicitly requested`() {
        val project = ProjectBuilder.builder().build()
        val extension = project.objects.newInstance(
            AndroidHardeningExtension::class.java,
            project.objects,
            project.layout,
        )
        extension.projectKey.set("demo")
        extension.variants.include("demoRelease")
        extension.code.diversification.minimumCoverage.set(1.01)

        val failure = assertFailsWith<IllegalArgumentException> { extension.validateV1() }

        assertTrue(failure.message.orEmpty().contains("minimumCoverage"))
    }

    @Test
    fun `v1 mapping safety flags cannot be silently disabled`() {
        val project = ProjectBuilder.builder().build()
        val extension = project.objects.newInstance(
            AndroidHardeningExtension::class.java,
            project.objects,
            project.layout,
        )
        extension.projectKey.set("demo")
        extension.variants.include("demoRelease")
        extension.mapping.reusePrevious.set(false)

        val failure = assertFailsWith<IllegalArgumentException> { extension.validateV1() }

        assertTrue(failure.message.orEmpty().contains("reusePrevious"))
    }

    @Test
    fun `relative improvement threshold has a strict positive lower bound`() {
        val project = ProjectBuilder.builder().build()
        val extension = project.objects.newInstance(
            AndroidHardeningExtension::class.java,
            project.objects,
            project.layout,
        )
        extension.projectKey.set("demo")
        extension.variants.include("demoDebug")
        extension.similarity.minimumImprovementPoints.set(0.009)

        val failure = assertFailsWith<IllegalArgumentException> { extension.validateV1() }

        assertTrue(failure.message.orEmpty().contains("minimumImprovementPoints"))
    }

    @Test
    fun `v1 rejects absolute and growth similarity enforcement`() {
        val project = ProjectBuilder.builder().build()
        val extension = project.objects.newInstance(
            AndroidHardeningExtension::class.java,
            project.objects,
            project.layout,
        )
        extension.projectKey.set("demo")
        extension.variants.include("demoDebug")
        extension.similarity.enforceMaximumOverall.set(true)

        val failure = assertFailsWith<IllegalArgumentException> { extension.validateV1() }

        assertTrue(failure.message.orEmpty().contains("enforceMaximumOverall"))
    }

    @Test
    fun `v1 requires exactly thirty production stability seconds`() {
        val project = ProjectBuilder.builder().build()
        val extension = project.objects.newInstance(
            AndroidHardeningExtension::class.java,
            project.objects,
            project.layout,
        )
        extension.projectKey.set("demo")
        extension.variants.include("demoDebug")
        extension.deviceAcceptance.stabilitySeconds.set(29)

        val failure = assertFailsWith<IllegalArgumentException> { extension.validateV1() }

        assertTrue(failure.message.orEmpty().contains("must be 30"))
    }
}
