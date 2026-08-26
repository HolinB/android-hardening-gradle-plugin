package com.holin.android.hardening

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertTrue

class PortableOwnershipStaticScanTest {
    @Test
    fun `core ownership pipeline contains no fixed project scope`() {
        val sourceRoot = sourceRoot()
        val violations = OWNERSHIP_PIPELINE_FILES.flatMap { relative ->
            val source = sourceRoot.resolve(relative).readText()
            FORBIDDEN_IDENTIFIERS.filter(source::contains).map { identifier -> "$relative -> $identifier" }
        }

        assertTrue(violations.isEmpty(), violations.joinToString(prefix = "fixed ownership remains:\n"))
    }

    private fun sourceRoot(): Path {
        val candidates = listOf(
            Path.of("build-logic/src/main/kotlin"),
            Path.of("src/main/kotlin"),
        ).map(Path::toAbsolutePath).map(Path::normalize)
        return candidates.singleOrNull { it.exists() && Files.isDirectory(it) }
            ?: error("cannot locate build-logic production source root from ${Path.of("").toAbsolutePath()}")
    }

    private companion object {
        val OWNERSHIP_PIPELINE_FILES = listOf(
            "com/holin/android/hardening/audit/HardeningSourceAuditScanner.kt",
            "com/holin/android/hardening/code/OwnedBytecodeInventory.kt",
            "com/holin/android/hardening/inventory/OwnedDexInventoryBuilder.kt",
            "com/holin/android/hardening/r8/HardeningRulesFilter.kt",
            "com/holin/android/hardening/r8/RuleManifest.kt",
            "com/holin/android/hardening/resources/OwnedResourceInventoryBuilder.kt",
        )
        val FORBIDDEN_IDENTIFIERS = listOf(
            "HardeningOwnedModules",
            "demo",
            "luck",
            "yalantis",
            "chad",
            "BRVAH",
        )
    }
}
