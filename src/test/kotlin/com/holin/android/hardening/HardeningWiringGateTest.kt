package com.holin.android.hardening

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class HardeningWiringGateTest {
    @Test
    fun `forbidden graph classifier uses action categories and no brand substring`() {
        assertEquals(
            listOf(
                ":core:installPreview",
                ":media:notifyRelease",
                ":mobile:publishRemoteArtifact",
                ":mobile:uploadArtifact",
            ),
            HardeningWiringGate.forbiddenTaskNames(
                listOf(
                    ":mobile:prepareHardeningQuietDebug",
                    ":publisher:prepareHardeningDemo",
                    ":core:assembleShowcaseRelease",
                    ":media:compileDemoRelease",
                    ":core:publisherMetadata",
                    ":core:installerSetup",
                    ":core:notifierSync",
                    ":core:uploaderStatus",
                    ":mobile:uploadArtifact",
                    ":mobile:publishRemoteArtifact",
                    ":core:installPreview",
                    ":media:notifyRelease",
                ),
            ),
        )
    }

    @Test
    fun `only an explicit true project property enables AGP transforms`() {
        assertTrue(HardeningWiringGate.isEnabled(mapOf("androidHardening" to "true")))
        assertTrue(HardeningWiringGate.isEnabled(mapOf("androidHardening" to "TRUE")))
        assertFalse(HardeningWiringGate.isEnabled(emptyMap()))
        assertFalse(HardeningWiringGate.isEnabled(mapOf("androidHardening" to "false")))
        assertFalse(HardeningWiringGate.isEnabled(mapOf("androidHardening" to "1")))
    }

    @Test
    fun `variant selection is exact and case sensitive`() {
        val included = setOf("demoRelease")

        assertTrue(HardeningWiringGate.isSelected("demoRelease", included))
        assertFalse(HardeningWiringGate.isSelected("demoDebug", included))
        assertFalse(HardeningWiringGate.isSelected("DemoRelease", included))
    }

    @Test
    fun `hardening invocation selection requires a hardening task for the exact variant`() {
        assertTrue(
            HardeningWiringGate.isHardeningTaskRequested(
                "demoDebug",
                listOf(":app:hardeningAssembleDemoDebug"),
            ),
        )
        assertTrue(
            HardeningWiringGate.isHardeningTaskRequested(
                "demoDebug",
                listOf("rewriteHardeningDemoDebugBundle"),
            ),
        )
        listOf(
            "captureHardeningBaselineDemoDebug",
            "compareHardeningDemoDebug",
            "compareExternalHardeningDemoDebug",
            "hardeningRunDemoDebug",
            "generateHardeningDemoDebugCodeMapping",
        ).forEach { task ->
            assertTrue(HardeningWiringGate.isHardeningTaskRequested("demoDebug", listOf(task)), task)
        }
        assertFalse(
            HardeningWiringGate.isHardeningTaskRequested(
                "demoDebug",
                listOf("smokeHardeningDemoDebug"),
            ),
        )
        assertFalse(
            HardeningWiringGate.isHardeningTaskRequested(
                "demoDebug",
                listOf("assembleDemoDebug"),
            ),
        )
        assertFalse(
            HardeningWiringGate.isHardeningTaskRequested(
                "demoDebug",
                listOf("hardeningAssembleDemoRelease"),
            ),
        )
        assertFalse(
            HardeningWiringGate.isHardeningTaskRequested(
                variantName = "demoDebug",
                requestedTasks = listOf(":other:hardeningAssembleDemoDebug"),
                projectPath = ":app",
            ),
        )
        assertFalse(
            HardeningWiringGate.isHardeningTaskRequested(
                "demoDebug",
                listOf("rewriteHardeningDemoDebugReleaseBundle"),
            ),
        )
    }

    @Test
    fun `requested selected variants map to their exact build types`() {
        val requested = HardeningWiringGate.requestedBuildTypes(
            requestedTasks = listOf("hardeningAssembleDemoDebug"),
            includedVariants = setOf("demoDebug", "demoRelease"),
            buildTypes = setOf("debug", "release"),
        )

        assertEquals(setOf("debug"), requested)
        assertEquals(
            setOf("debug"),
            HardeningWiringGate.requestedBuildTypes(
                requestedTasks = listOf(":app:hardeningRunDemoDebug"),
                includedVariants = setOf("demoDebug"),
                buildTypes = setOf("debug", "release"),
            ),
        )
        assertEquals(
            emptySet(),
            HardeningWiringGate.requestedBuildTypes(
                requestedTasks = listOf("assembleDemoDebug"),
                includedVariants = setOf("demoDebug", "demoRelease"),
                buildTypes = setOf("debug", "release"),
            ),
        )
        assertEquals(
            setOf("stagingDebug"),
            HardeningWiringGate.requestedBuildTypes(
                requestedTasks = listOf("hardeningAssembleDemoStagingDebug"),
                includedVariants = setOf("demoStagingDebug"),
                buildTypes = setOf("debug", "stagingDebug"),
            ),
        )
    }

    @Test
    fun `device execution authorization requires run for the exact project and variant`() {
        assertTrue(
            HardeningWiringGate.isHardeningRunRequested(
                "demoDebug",
                listOf(":app:hardeningRunDemoDebug"),
                projectPath = ":app",
            ),
        )
        assertFalse(
            HardeningWiringGate.isHardeningRunRequested(
                "demoDebug",
                listOf(":other:hardeningRunDemoDebug"),
                projectPath = ":app",
            ),
        )
        assertFalse(
            HardeningWiringGate.isHardeningRunRequested(
                "demoDebug",
                listOf(":app:smokeHardeningDemoDebug"),
                projectPath = ":app",
            ),
        )
    }

    @Test
    fun `hardening invocation rejects unrelated tasks in the same project`() {
        assertEquals(
            listOf(":app:assembleShowcaseDebug"),
            HardeningWiringGate.conflictingProjectArtifactTasks(
                requestedTasks = listOf(
                    ":app:hardeningAssembleDemoDebug",
                    ":app:assembleShowcaseDebug",
                    ":app:dumpDemoDebugProguardFiles",
                    ":core:compileShowcaseDebugKotlin",
                    "clean",
                ),
                includedVariants = setOf("demoDebug", "demoRelease"),
                projectPath = ":app",
            ),
        )
    }
}
