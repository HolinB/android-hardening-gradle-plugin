package com.holin.android.hardening.audit

import com.holin.android.hardening.LegacyPluginDeclaration
import com.holin.android.hardening.HardcodedReferenceKind
import com.holin.android.hardening.state.Sha256
import com.holin.android.hardening.state.StrictJson
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.Base64

enum class HardeningAuditStatus { PASS, FAIL }
enum class LegacyCompatibilityStatus { PASS, FAIL, NOT_APPLICABLE }

data class RuntimeArtifactInput(val component: String, val file: Path)
data class RuntimeDependencyEntry(
    val component: String,
    val fileName: String,
    val sha256: String,
    val size: Long,
)

data class LegacyPluginObservation(
    val pluginId: String,
    val implementationClass: String,
    val implementationArtifact: String,
    val implementationSha256: String,
    val extensionName: String,
    val extensionClass: String,
    val taskNames: List<String>,
    val taskClasses: List<String>,
)

data class LegacyCompatibilityResult(
    val status: LegacyCompatibilityStatus,
    val plugins: List<LegacyPluginObservation>,
    val issues: List<String>,
)

data class HardcodedReferenceScopeReport(
    val kinds: List<String>,
    val includeGlobs: List<String>,
    val excludeGlobs: List<String>,
    val failOnUnresolvedOwnedReference: Boolean,
)

data class HardeningAuditReport(
    val variant: String,
    val namespace: String,
    val status: HardeningAuditStatus,
    val productionSourceFiles: List<String>,
    val resolvedContracts: List<ResolvedContract>,
    val unresolvedContracts: List<UnresolvedContract>,
    val externalNameCandidates: List<ExternalNameCandidate>,
    val legacyCompatibility: LegacyCompatibilityResult,
    val runtimeDependencies: List<RuntimeDependencyEntry>,
    val r8RulesManifestSha256: String,
    val webpDiversificationFiles: List<String> = emptyList(),
    val hardcodedReferenceScope: HardcodedReferenceScopeReport = HardcodedReferenceScopeReport(emptyList(), emptyList(), emptyList(), true),
    val hardcodedReferenceFindings: List<HardcodedReferenceFinding> = emptyList(),
    val unresolvedHardcodedReferences: List<UnresolvedHardcodedReference> = emptyList(),
)

class RuntimeDependencyFingerprinter {
    fun fingerprint(inputs: List<RuntimeArtifactInput>): List<RuntimeDependencyEntry> = inputs.map { input ->
        val path = input.file.toAbsolutePath().normalize()
        require(Files.isRegularFile(path, NOFOLLOW_LINKS) && !Files.isSymbolicLink(path)) {
            "release runtime dependency is not a regular non-symlink file: $path"
        }
        RuntimeDependencyEntry(
            component = input.component,
            fileName = path.fileName.toString(),
            sha256 = Sha256.file(path),
            size = Files.size(path),
        )
    }.sortedWith(compareBy({ it.component }, { it.fileName }, { it.sha256 }))
}

object LegacyCompatibilityVerifier {
    fun verify(
        observations: List<LegacyPluginObservation>,
        declarations: List<LegacyPluginDeclaration> = emptyList(),
    ): LegacyCompatibilityResult {
        if (observations.isEmpty() && declarations.isEmpty()) {
            return LegacyCompatibilityResult(LegacyCompatibilityStatus.NOT_APPLICABLE, emptyList(), emptyList())
        }
        val sorted = observations.sortedBy(LegacyPluginObservation::pluginId)
        val byId = sorted.associateBy(LegacyPluginObservation::pluginId)
        require(byId.size == sorted.size) { "duplicate legacy plugin observations" }
        val declarationsById = declarations.associateBy(LegacyPluginDeclaration::pluginId)
        require(declarationsById.size == declarations.size) { "duplicate legacy plugin declarations" }
        val issues = buildList {
            declarations.sortedBy(LegacyPluginDeclaration::name).forEach { expected ->
                val actual = byId[expected.pluginId]
                if (actual == null) {
                    add("legacy plugin ${expected.pluginId} ${expected.expectedVersion} is missing")
                    return@forEach
                }
                if (actual.implementationClass.isBlank()) {
                    add("legacy plugin ${expected.pluginId} implementation class is missing")
                }
                if (!artifactHasVersion(actual.implementationArtifact, expected.expectedVersion)) {
                    add("legacy plugin ${expected.pluginId} artifact does not identify pinned version ${expected.expectedVersion}")
                }
                if (actual.extensionName.isBlank() || actual.extensionClass.isBlank()) {
                    add("legacy plugin ${expected.pluginId} extension identity is missing")
                }
                if (actual.taskNames.isEmpty() || actual.taskClasses.isEmpty()) {
                    add("legacy plugin ${expected.pluginId} task identity is missing")
                }
                if (!actual.implementationSha256.matches(SHA256)) {
                    add("legacy plugin ${expected.pluginId} implementation checksum is invalid")
                }
            }
            (byId.keys - declarationsById.keys).sorted().forEach { id ->
                add("unexpected legacy plugin observation $id")
            }
        }.sorted()
        return LegacyCompatibilityResult(
            if (issues.isEmpty()) LegacyCompatibilityStatus.PASS else LegacyCompatibilityStatus.FAIL,
            sorted,
            issues,
        )
    }

    private fun artifactHasVersion(artifact: String, version: String): Boolean =
        Regex("(?:^|[-_.])${Regex.escape(version)}(?:[-_.]|\\.jar$)").containsMatchIn(artifact)

    private val SHA256 = Regex("[0-9a-f]{64}")
}

object RuntimeArtifactInputCodec {
    fun encode(component: String, file: Path): String = listOf(component, file.toAbsolutePath().normalize().toString())
        .joinToString(SEPARATOR) { encodeField(it) }

    fun decode(value: String): RuntimeArtifactInput {
        val fields = value.split(SEPARATOR)
        require(fields.size == 2) { "invalid runtime artifact input" }
        return RuntimeArtifactInput(decodeField(fields[0]), Path.of(decodeField(fields[1])))
    }

    private const val SEPARATOR = "."
}

object LegacyPluginObservationCodec {
    fun encode(observation: LegacyPluginObservation): String = listOf(
        observation.pluginId,
        observation.implementationClass,
        observation.implementationArtifact,
        observation.implementationSha256,
        observation.extensionName,
        observation.extensionClass,
        observation.taskNames.sorted().joinToString(LIST_SEPARATOR),
        observation.taskClasses.sorted().joinToString(LIST_SEPARATOR),
    ).joinToString(FIELD_SEPARATOR) { encodeField(it) }

    fun decode(value: String): LegacyPluginObservation {
        val fields = value.split(FIELD_SEPARATOR).map(::decodeField)
        require(fields.size == 8) { "invalid legacy plugin observation" }
        return LegacyPluginObservation(
            pluginId = fields[0],
            implementationClass = fields[1],
            implementationArtifact = fields[2],
            implementationSha256 = fields[3],
            extensionName = fields[4],
            extensionClass = fields[5],
            taskNames = splitList(fields[6]),
            taskClasses = splitList(fields[7]),
        )
    }

    private fun splitList(value: String): List<String> = if (value.isEmpty()) emptyList() else value.split(LIST_SEPARATOR)
    private const val FIELD_SEPARATOR = "."
    private const val LIST_SEPARATOR = "\u001f"
}

private fun encodeField(value: String): String = Base64.getUrlEncoder().withoutPadding()
    .encodeToString(value.toByteArray(Charsets.UTF_8))

private fun decodeField(value: String): String = String(Base64.getUrlDecoder().decode(value), Charsets.UTF_8)

object HardeningAuditReportCodec {
    fun encode(report: HardeningAuditReport): String = buildString {
        append("{\"schemaVersion\":1")
        append(",\"variant\":").append(json(report.variant))
        append(",\"namespace\":").append(json(report.namespace))
        append(",\"status\":").append(json(report.status.name))
        append(",\"productionSourceFiles\":[")
        report.productionSourceFiles.sorted().forEachIndexed { index, file ->
            if (index > 0) append(',')
            append(json(file))
        }
        append("]")
        append(",\"webpDiversificationFiles\":[")
        report.webpDiversificationFiles.sorted().forEachIndexed { index, file ->
            if (index > 0) append(',')
            append(json(file))
        }
        append("]")
        append(",\"hardcodedReferenceScope\":{\"kinds\":[")
        report.hardcodedReferenceScope.kinds.sorted().forEachIndexed { index, kind ->
            if (index > 0) append(',')
            append(json(kind))
        }
        append("],\"includeGlobs\":[")
        report.hardcodedReferenceScope.includeGlobs.sorted().forEachIndexed { index, glob ->
            if (index > 0) append(',')
            append(json(glob))
        }
        append("],\"excludeGlobs\":[")
        report.hardcodedReferenceScope.excludeGlobs.sorted().forEachIndexed { index, glob ->
            if (index > 0) append(',')
            append(json(glob))
        }
        append("],\"failOnUnresolvedOwnedReference\":")
        append(report.hardcodedReferenceScope.failOnUnresolvedOwnedReference)
        append('}')
        append(",\"hardcodedReferenceFindings\":[")
        report.hardcodedReferenceFindings
            .sortedWith(compareBy({ it.sourceFile }, { it.line }, { it.kind.name }, { it.value }))
            .forEachIndexed { index, finding ->
                if (index > 0) append(',')
                val reportedValue = reportedHardcodedValue(finding)
                append("{\"kind\":").append(json(finding.kind.name))
                append(",\"sourceFile\":").append(json(finding.sourceFile))
                append(",\"line\":").append(finding.line)
                append(",\"value\":").append(json(reportedValue.value))
                reportedValue.sha256?.let { append(",\"valueSha256\":").append(json(it)) }
                finding.ownerInternalName?.let { append(",\"ownerInternalName\":").append(json(it)) }
                finding.jvmDescriptor?.let { append(",\"jvmDescriptor\":").append(json(it)) }
                append('}')
            }
        append("]")
        append(",\"unresolvedHardcodedReferences\":[")
        report.unresolvedHardcodedReferences
            .sortedWith(compareBy({ it.sourceFile }, { it.line }, { it.kind.name }, { it.expression }))
            .forEachIndexed { index, finding ->
                if (index > 0) append(',')
                append("{\"kind\":").append(json(finding.kind.name))
                append(",\"sourceFile\":").append(json(finding.sourceFile))
                append(",\"line\":").append(finding.line)
                append(",\"expression\":").append(json(finding.expression))
                append(",\"reason\":").append(json(finding.reason)).append('}')
            }
        append("]")
        append(",\"resolvedContracts\":[")
        report.resolvedContracts.sortedWith(compareBy({ it.sourceFile }, { it.line }, { it.kind.name }, { it.resolvedName }))
            .forEachIndexed { index, contract ->
                if (index > 0) append(',')
                append("{\"kind\":").append(json(contract.kind.name))
                append(",\"sourceFile\":").append(json(contract.sourceFile))
                append(",\"line\":").append(contract.line)
                append(",\"resolvedName\":").append(json(contract.resolvedName))
                append(",\"expression\":").append(json(contract.expression)).append('}')
            }
        append("]")
        append(",\"unresolvedContracts\":[")
        report.unresolvedContracts.sortedWith(compareBy({ it.sourceFile }, { it.line }, { it.kind.name }, { it.expression }))
            .forEachIndexed { index, contract ->
                if (index > 0) append(',')
                append("{\"kind\":").append(json(contract.kind.name))
                append(",\"sourceFile\":").append(json(contract.sourceFile))
                append(",\"line\":").append(contract.line)
                append(",\"expression\":").append(json(contract.expression))
                append(",\"reason\":").append(json(contract.reason)).append('}')
            }
        append("]")
        append(",\"externalNameCandidates\":[")
        report.externalNameCandidates.sortedWith(compareBy({ it.sourceFile }, { it.line }, { it.kind.name }, { it.symbol }))
            .forEachIndexed { index, candidate ->
                if (index > 0) append(',')
                append("{\"kind\":").append(json(candidate.kind.name))
                append(",\"sourceFile\":").append(json(candidate.sourceFile))
                append(",\"line\":").append(candidate.line)
                append(",\"symbol\":").append(json(candidate.symbol))
                append(",\"action\":").append(json(candidate.action.name)).append('}')
            }
        append("]")
        append(",\"legacyCompatibility\":{")
        append("\"status\":").append(json(report.legacyCompatibility.status.name))
        append(",\"issues\":[")
        report.legacyCompatibility.issues.sorted().forEachIndexed { index, issue ->
            if (index > 0) append(',')
            append(json(issue))
        }
        append("],\"plugins\":[")
        report.legacyCompatibility.plugins.sortedBy(LegacyPluginObservation::pluginId).forEachIndexed { index, plugin ->
            if (index > 0) append(',')
            append("{\"pluginId\":").append(json(plugin.pluginId))
            append(",\"implementationClass\":").append(json(plugin.implementationClass))
            append(",\"implementationArtifact\":").append(json(plugin.implementationArtifact))
            append(",\"implementationSha256\":").append(json(plugin.implementationSha256))
            append(",\"extensionName\":").append(json(plugin.extensionName))
            append(",\"extensionClass\":").append(json(plugin.extensionClass))
            append(",\"taskNames\":[")
            plugin.taskNames.sorted().forEachIndexed { taskIndex, task ->
                if (taskIndex > 0) append(',')
                append(json(task))
            }
            append("],\"taskClasses\":[")
            plugin.taskClasses.sorted().forEachIndexed { taskIndex, task ->
                if (taskIndex > 0) append(',')
                append(json(task))
            }
            append("]}")
        }
        append("]}")
        append(",\"runtimeDependencies\":[")
        report.runtimeDependencies.sortedWith(compareBy({ it.component }, { it.fileName }, { it.sha256 }))
            .forEachIndexed { index, dependency ->
                if (index > 0) append(',')
                append("{\"component\":").append(json(dependency.component))
                append(",\"fileName\":").append(json(dependency.fileName))
                append(",\"sha256\":").append(json(dependency.sha256))
                append(",\"size\":").append(dependency.size).append('}')
            }
        append("]")
        append(",\"r8RulesManifestSha256\":").append(json(report.r8RulesManifestSha256))
        append("}\n")
    }

    private fun reportedHardcodedValue(finding: HardcodedReferenceFinding): ReportedHardcodedValue {
        if (finding.kind != HardcodedReferenceKind.URL && finding.kind != HardcodedReferenceKind.URI) {
            return ReportedHardcodedValue(finding.value, null)
        }
        val scheme = finding.value.substringBefore("://").lowercase()
        return ReportedHardcodedValue(
            "$scheme://<redacted>",
            Sha256.hex(finding.value.toByteArray(Charsets.UTF_8)),
        )
    }

    private data class ReportedHardcodedValue(val value: String, val sha256: String?)

    fun decodeStatus(document: String): HardeningAuditStatus {
        StrictJson.validateDocument(document)
        val match = STATUS.find(document) ?: throw IllegalArgumentException("hardening audit report status is missing")
        return runCatching { HardeningAuditStatus.valueOf(match.groupValues[1]) }
            .getOrElse { throw IllegalArgumentException("hardening audit report status is invalid", it) }
    }

    fun requirePassing(document: String) {
        require(decodeStatus(document) == HardeningAuditStatus.PASS) { "hardening audit report is not PASS" }
    }

    private fun json(value: String): String = buildString {
        append('"')
        value.forEach { character ->
            when (character) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\b' -> append("\\b")
                '\u000c' -> append("\\f")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (character.code < 0x20) append("\\u%04x".format(character.code)) else append(character)
            }
        }
        append('"')
    }

    private val STATUS = Regex("""\"status\"\s*:\s*\"(PASS|FAIL)\"""")
}
