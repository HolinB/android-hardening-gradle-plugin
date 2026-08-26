package com.holin.android.hardening.verification

import com.android.tools.r8.Diagnostic
import com.android.tools.r8.DiagnosticsHandler
import com.android.tools.r8.Version
import com.android.tools.r8.retrace.ProguardMapProducer
import com.android.tools.r8.retrace.ProguardMappingSupplier
import com.android.tools.r8.retrace.Retrace
import com.android.tools.r8.retrace.RetraceCommand
import java.nio.file.Path

data class RetraceVerificationResult(
    val r8Version: String,
    val candidate: RetraceCandidate,
    val retracedFrames: List<String>,
    val diagnostics: List<String>,
    val verified: Boolean,
)

class OfficialRetraceVerifier {
    fun selectCandidate(mapping: ParsedR8Mapping): RetraceCandidate = mapping.retraceCandidates
        .sortedWith(
            compareByDescending<RetraceCandidate> {
                it.originalClass != it.obfuscatedClass || it.originalMethod != it.obfuscatedMethod
            }.thenBy(RetraceCandidate::originalClass)
                .thenBy(RetraceCandidate::originalMethod)
                .thenBy(RetraceCandidate::originalLine),
        )
        .firstOrNull()
        ?: throw IllegalArgumentException("current app R8 mapping contains no exact positive line mapping for Retrace")

    fun verify(
        mapping: Path,
        candidate: RetraceCandidate,
        expectedR8Version: String,
    ): RetraceVerificationResult {
        val version = runtimeVersion()
        if (version != expectedR8Version) {
            return RetraceVerificationResult(
                version,
                candidate,
                emptyList(),
                listOf(
                    "official R8 Retrace version $version differs from mapping compiler version $expectedR8Version",
                ),
                false,
            )
        }
        val diagnostics = CollectingDiagnosticsHandler()
        var retraced = emptyList<String>()
        try {
            val mappingSupplier = ProguardMappingSupplier.builder()
                .setProguardMapProducer(ProguardMapProducer.fromPath(mapping))
                .setLoadAllDefinitions(true)
                .build()
            val command = RetraceCommand.builder(diagnostics)
                .setMappingSupplier(mappingSupplier)
                .setStackTrace(listOf(candidate.obfuscatedFrame))
                .setVerbose(false)
                .setRetracedStackTraceConsumer { frames -> retraced = frames.toList() }
                .build()
            Retrace.run(command)
        } catch (failure: RuntimeException) {
            diagnostics.failures += "Retrace failed: ${failure.javaClass.simpleName}"
        }
        val restored = retraced.asSequence()
            .mapNotNull(RETRACED_FRAME::matchEntire)
            .any { match ->
                match.groupValues[1] == candidate.originalClass &&
                    match.groupValues[2] == candidate.originalMethod &&
                    match.groupValues[3].toIntOrNull() == candidate.originalLine
            }
        return RetraceVerificationResult(
            version,
            candidate,
            retraced,
            diagnostics.messages.sorted(),
            restored && diagnostics.failures.isEmpty(),
        )
    }

    fun runtimeVersion(): String =
        "${Version.getMajorVersion()}.${Version.getMinorVersion()}.${Version.getPatchVersion()}"

    private class CollectingDiagnosticsHandler : DiagnosticsHandler {
        val failures = mutableListOf<String>()
        private val warnings = mutableListOf<String>()
        val messages: List<String> get() = failures + warnings

        override fun error(diagnostic: Diagnostic) {
            failures += "error: ${diagnostic.diagnosticMessage}"
        }

        override fun warning(diagnostic: Diagnostic) {
            warnings += "warning: ${diagnostic.diagnosticMessage}"
        }
    }

    companion object {
        private val RETRACED_FRAME = Regex("^\\s*at\\s+(.+)\\.([^.(]+)\\([^:()]*:(\\d+)\\)\\s*$")
    }
}
