package com.holin.android.hardening.audit

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertTrue

class PortableLegacyPluginStaticScanTest {
    @Test
    fun `legacy compatibility core contains no project plugin identities`() {
        val sourceRoot = listOf(
            Path.of("build-logic/src/main/kotlin"),
            Path.of("src/main/kotlin"),
        ).map(Path::toAbsolutePath).map(Path::normalize)
            .singleOrNull { it.exists() && Files.isDirectory(it) }
            ?: error("cannot locate build-logic production source root")
        val violations = CORE_FILES.flatMap { relative ->
            val source = sourceRoot.resolve(relative).readText()
            FORBIDDEN_IDENTIFIERS.filter(source::contains).map { identifier -> "$relative -> $identifier" }
        }

        assertTrue(violations.isEmpty(), violations.joinToString(prefix = "fixed legacy plugin identity remains:\n"))
    }

    private companion object {
        val CORE_FILES = listOf(
            "com/holin/android/hardening/audit/HardeningAuditReport.kt",
            "com/holin/android/hardening/audit/LegacyPluginBaselineVerifier.kt",
            "com/holin/android/hardening/audit/LegacyPluginProbe.kt",
        )
        val FORBIDDEN_IDENTIFIERS = listOf(
            "android-junk-code",
            "xml-class-guard",
            "stringfog",
            "cn.hx.plugin.junkcode",
            "com.xml.guard",
            "megatronking",
        )
    }
}
