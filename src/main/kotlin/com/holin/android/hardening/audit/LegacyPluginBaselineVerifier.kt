package com.holin.android.hardening.audit

import com.holin.android.hardening.LegacyPluginDeclaration
import com.holin.android.hardening.state.Sha256
import com.holin.android.hardening.state.StrictJson
import groovy.json.JsonSlurper
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path

object LegacyPluginBaselineVerifier {
    fun verifyRequired(
        baselineFile: Path?,
        repositoryRoot: Path,
        observations: List<LegacyPluginObservation>,
        declarations: List<LegacyPluginDeclaration> = emptyList(),
    ): LegacyCompatibilityResult = verify(
        requireNotNull(baselineFile) { "legacy plugin baseline is required for a full hardening audit" },
        repositoryRoot,
        observations,
        declarations,
    )

    fun verify(
        baselineFile: Path,
        repositoryRoot: Path,
        observations: List<LegacyPluginObservation>,
        declarations: List<LegacyPluginDeclaration> = emptyList(),
    ): LegacyCompatibilityResult {
        val root = repositoryRoot.toAbsolutePath().normalize()
        val baseline = readBaseline(baselineFile, root)

        val sourceIssues = verifyFrozenSources(root, baseline)
        val expectations = pluginExpectations(baseline)
        verifyPluginPaths(root, expectations)
        val sorted = observations.sortedBy(LegacyPluginObservation::pluginId)
        val byId = sorted.associateBy(LegacyPluginObservation::pluginId)
        require(byId.size == sorted.size) { "duplicate legacy plugin observations" }
        val observationIssues = buildList {
            expectations.forEach { expected ->
                val actual = byId[expected.pluginId]
                if (actual == null) {
                    add("legacy plugin ${expected.pluginId} ${expected.expectedVersion} is missing")
                    return@forEach
                }
                if (actual.implementationClass != expected.implementationClass) {
                    add("legacy plugin ${expected.pluginId} implementation class differs from ${expected.implementationClass}")
                }
                if (!artifactHasVersion(actual.implementationArtifact, expected.expectedVersion)) {
                    add("legacy plugin ${expected.pluginId} artifact does not identify pinned version ${expected.expectedVersion}")
                }
                if (actual.extensionName != expected.extensionName) {
                    add("legacy plugin ${expected.pluginId} extension name differs from ${expected.extensionName}")
                }
                if (actual.extensionClass != expected.extensionClass) {
                    add("legacy plugin ${expected.pluginId} extension class differs from ${expected.extensionClass}")
                }
                if (actual.taskNames != expected.taskNames) {
                    add("legacy plugin ${expected.pluginId} task names differ from its pinned baseline")
                }
                if (actual.taskClasses != expected.taskClasses) {
                    add("legacy plugin ${expected.pluginId} task classes differ from its pinned baseline")
                }
                if (!actual.implementationSha256.matches(SHA256)) {
                    add("legacy plugin ${expected.pluginId} implementation checksum is invalid")
                } else if (actual.implementationSha256 != expected.jarSha256) {
                    add("legacy plugin ${expected.pluginId} implementation checksum differs from its pinned baseline")
                }
            }
            (byId.keys - expectations.mapTo(linkedSetOf(), PluginExpectation::pluginId)).sorted().forEach { id ->
                add("unexpected legacy plugin observation $id")
            }
        }
        val declarationIssues = if (declarations.isEmpty()) emptyList() else verifyDeclarations(expectations, declarations)
        val issues = (sourceIssues + observationIssues + declarationIssues).sorted()
        return LegacyCompatibilityResult(
            status = if (issues.isEmpty()) LegacyCompatibilityStatus.PASS else LegacyCompatibilityStatus.FAIL,
            plugins = sorted,
            issues = issues,
        )
    }

    internal fun probeExpectations(
        baselineFile: Path,
        repositoryRoot: Path,
        declarations: List<LegacyPluginDeclaration>,
    ): List<LegacyPluginProbeExpectation> {
        val root = repositoryRoot.toAbsolutePath().normalize()
        val expectations = pluginExpectations(readBaseline(baselineFile, root))
        verifyPluginPaths(root, expectations)
        val declarationIssues = verifyDeclarations(expectations, declarations)
        require(declarationIssues.isEmpty()) { declarationIssues.sorted().joinToString("; ") }
        return expectations.map { expectation ->
            val concreteTaskClasses = expectation.taskClasses.filterNot { taskClass ->
                taskClass == "java.lang.Object" || taskClass.startsWith("org.gradle.")
            }.toSet()
            require(concreteTaskClasses.isNotEmpty()) {
                "legacy plugin ${expectation.name} baseline has no concrete task class"
            }
            LegacyPluginProbeExpectation(
                expectation.pluginId,
                expectation.extensionName,
                concreteTaskClasses,
            )
        }
    }

    private fun readBaseline(baselineFile: Path, root: Path): Map<String, Any?> {
        val baselinePath = requireRegularInput(baselineFile, root, "legacy plugin baseline")
        val baselineText = readUtf8(baselinePath, "legacy plugin baseline")
        StrictJson.validateDocument(baselineText)
        val baseline = JsonSlurper().parseText(baselineText).asStringMap("legacy plugin baseline")
        require(baseline.keys == REQUIRED_BASELINE_KEYS) {
            "legacy plugin baseline fields differ from the frozen schema"
        }
        require(baseline.number("schemaVersion").toInt() == 3) {
            "legacy plugin baseline schemaVersion must be 3"
        }
        return baseline
    }

    private fun verifyFrozenSources(root: Path, baseline: Map<String, Any?>): List<String> {
        val capture = baseline.map("capture")
        require(capture.keys == CAPTURE_KEYS) { "legacy plugin capture metadata fields differ from the frozen schema" }
        require(capture.string("hashAlgorithm") == "SHA-256") { "legacy plugin baseline hashAlgorithm must be SHA-256" }
        require(capture.string("encoding") == "UTF-8") { "legacy plugin baseline encoding must be UTF-8" }
        require(capture.string("lineEndings") == "raw") { "legacy plugin baseline lineEndings must be raw" }
        require(capture.string("regionBoundary") == "start-inclusive-end-exclusive") {
            "legacy plugin baseline regionBoundary is unsupported"
        }
        val provenance = capture.map("sourceProvenance")
        val regions = capture.map("regions")
        val frozen = baseline.map("frozenRegions")
        require(regions.isNotEmpty() && regions.keys == frozen.keys) {
            "legacy plugin baseline frozen region set is empty or inconsistent"
        }
        val sourceCache = mutableMapOf<String, String>()
        fun source(fileKey: String): String = sourceCache.getOrPut(fileKey) {
            val metadata = provenance.map(fileKey)
            require(metadata.keys == SOURCE_PROVENANCE_KEYS) {
                "legacy plugin source provenance $fileKey fields are invalid"
            }
            metadata.sha256("sha256")
            require(metadata.string("sourceRevision").startsWith("git-blob:")) {
                "legacy plugin source provenance $fileKey revision is invalid"
            }
            val relative = metadata.string("path")
            readUtf8(requireRegularInput(root.resolve(relative), root, "legacy plugin source $relative"), relative)
        }

        val issues = mutableListOf<String>()
        regions.forEach { (name, rawDefinition) ->
            val definition = rawDefinition.asStringMap("legacy plugin region $name")
            val fileKey = definition.string("file")
            val content = source(fileKey)
            val expected = frozen.map(name)
            require(expected.string("file") == fileKey) { "legacy plugin frozen region $name has inconsistent source" }
            val actualBytes = runCatching {
                when (definition.string("algorithm")) {
                    "ordered-exact-lines" -> {
                        val lines = definition.stringList("lines")
                        require(lines.isNotEmpty()) { "legacy plugin region $name has no exact lines" }
                        val positions = lines.map { line -> allPositions(content, line) }
                        if (positions.any { it.size != 1 }) {
                            issues += "frozen region mismatch: $name"
                        } else if (positions.map { it.single() } != positions.map { it.single() }.sorted()) {
                            issues += "frozen region mismatch: $name"
                        }
                        require(expected.number("lineCount").toInt() == lines.size) {
                            "legacy plugin frozen region $name line count is invalid"
                        }
                        lines.joinToString(separator = "").toByteArray(Charsets.UTF_8)
                    }
                    "balanced-brace-block" -> balancedBraceBlock(content, definition.string("startMarker"), name)
                        .toByteArray(Charsets.UTF_8)
                    else -> throw IllegalArgumentException("legacy plugin region $name uses an unsupported algorithm")
                }
            }.getOrElse {
                issues += "frozen region mismatch: $name"
                byteArrayOf()
            }
            val expectedHash = expected.sha256("sha256")
            if (Sha256.hex(actualBytes) != expectedHash) issues += "frozen region mismatch: $name"
        }

        val versionSources = baseline.map("versionSources")
        require(versionSources.isNotEmpty()) { "legacy plugin version source set is empty" }
        versionSources.forEach { (name, rawSource) ->
            val versionSource = rawSource.asStringMap("legacy plugin version source $name")
            require(versionSource.keys == setOf("path", "literal")) {
                "legacy plugin version source $name fields are invalid"
            }
            val relative = versionSource.string("path")
            val literal = versionSource.string("literal")
            val content = readUtf8(
                requireRegularInput(root.resolve(relative), root, "legacy plugin version source $relative"),
                relative,
            )
            if (!hasSingleActiveVersionDeclaration(content, literal)) {
                issues += "version source mismatch: $name"
            }
        }
        return issues.distinct()
    }

    private fun hasSingleActiveVersionDeclaration(content: String, literal: String): Boolean {
        val assignmentKey = literal.substringBefore('=', missingDelimiterValue = "").trim().takeIf(String::isNotEmpty)
        val pluginMarker = PLUGIN_ID.find(literal)?.value
        val declarations = if (assignmentKey != null) {
            val matches = mutableListOf<String>()
            var section = ""
            content.lineSequence().forEach { rawLine ->
                val line = stripLineComment(rawLine).trim()
                if (line.startsWith('[') && line.endsWith(']')) {
                    section = line.removeSurrounding("[", "]").trim()
                } else if (section == "versions" && line.substringBefore('=', missingDelimiterValue = "").trim() == assignmentKey) {
                    matches += line
                }
            }
            matches
        } else {
            content.lineSequence()
                .map(::stripLineComment)
                .map(String::trim)
                .filter(String::isNotEmpty)
                .filter { line -> pluginMarker != null && line.contains(pluginMarker) }
                .toList()
        }
        return declarations == listOf(literal)
    }

    private fun stripLineComment(line: String): String {
        var quote: Char? = null
        var escaped = false
        line.forEachIndexed { index, character ->
            if (quote != null) {
                if (character == quote && !escaped) quote = null
                escaped = character == '\\' && !escaped
                if (character != '\\') escaped = false
            } else {
                when {
                    character == '\'' || character == '"' -> quote = character
                    character == '#' -> return line.substring(0, index)
                    character == '/' && line.getOrNull(index + 1) == '/' -> return line.substring(0, index)
                }
            }
        }
        return line
    }

    private fun pluginExpectations(baseline: Map<String, Any?>): List<PluginExpectation> {
        val frozenRegionNames = baseline.map("frozenRegions").keys
        val versionSourceNames = baseline.map("versionSources").keys
        val plugins = baseline.objectList("plugins").map { plugin ->
            require(plugin.keys == PLUGIN_KEYS) {
                "legacy plugin baseline entry fields differ from the portable schema"
            }
            PluginExpectation(
                plugin.string("name"),
                plugin.string("pluginId"),
                plugin.string("expectedVersion"),
                plugin.string("implementationClass"),
                plugin.sha256("jarSha256"),
                plugin.string("extensionName"),
                plugin.string("extensionClass"),
                plugin.stringList("taskNames").sorted(),
                plugin.stringList("taskClasses").sorted(),
                plugin.stringList("configurationInputs").map(::requireRelativePath).sorted(),
                plugin.stringList("mappingPaths").map(::requireRelativePath).sorted(),
                plugin.stringList("frozenRegions").sorted(),
                plugin.stringList("versionSources").sorted(),
            )
        }.sortedBy(PluginExpectation::name)
        require(plugins.isNotEmpty()) { "legacy plugin baseline plugins must not be empty" }
        require(plugins.map(PluginExpectation::name).distinct().size == plugins.size) {
            "legacy plugin baseline contains duplicate declaration names"
        }
        require(plugins.map(PluginExpectation::pluginId).distinct().size == plugins.size) {
            "legacy plugin baseline contains duplicate pluginId values"
        }
        require(plugins.flatMap(PluginExpectation::frozenRegions).toSet() == frozenRegionNames) {
            "legacy plugin baseline frozen regions are not fully assigned"
        }
        require(plugins.flatMap(PluginExpectation::versionSources).toSet() == versionSourceNames) {
            "legacy plugin baseline version sources are not fully assigned"
        }
        plugins.forEach { plugin ->
            require(plugin.frozenRegions.all(frozenRegionNames::contains)) {
                "legacy plugin ${plugin.name} references an unknown frozen region"
            }
            require(plugin.versionSources.all(versionSourceNames::contains)) {
                "legacy plugin ${plugin.name} references an unknown version source"
            }
        }
        return plugins
    }

    private fun verifyDeclarations(
        expectations: List<PluginExpectation>,
        declarations: List<LegacyPluginDeclaration>,
    ): List<String> {
        val expectedByName = expectations.associateBy(PluginExpectation::name)
        val declaredByName = declarations.associateBy(LegacyPluginDeclaration::name)
        require(declaredByName.size == declarations.size) { "duplicate legacy plugin declarations" }
        return buildList {
            expectations.forEach { expected ->
                val declared = declaredByName[expected.name]
                if (declared == null) {
                    add("legacy plugin declaration ${expected.name} is missing")
                    return@forEach
                }
                if (declared.pluginId != expected.pluginId) {
                    add("legacy plugin ${expected.name} pluginId differs from its baseline")
                }
                if (declared.expectedVersion != expected.expectedVersion) {
                    add("legacy plugin ${expected.name} expectedVersion differs from its baseline")
                }
                if (declared.configurationInputs.sorted() != expected.configurationInputs) {
                    add("legacy plugin ${expected.name} configuration inputs differ from its baseline")
                }
                if (declared.mappingPaths.sorted() != expected.mappingPaths) {
                    add("legacy plugin ${expected.name} mapping paths differ from its baseline")
                }
            }
            (declaredByName.keys - expectedByName.keys).sorted().forEach { name ->
                add("unexpected legacy plugin declaration $name")
            }
        }
    }

    private fun requireRelativePath(value: String): String {
        val normalized = Path.of(value).normalize()
        require(!normalized.isAbsolute && normalized.toString().isNotEmpty() && !normalized.startsWith("..")) {
            "legacy plugin baseline path escapes the repository boundary: $value"
        }
        return normalized.toString().replace(java.io.File.separatorChar, '/')
    }

    private fun requireRegularInput(path: Path, root: Path, label: String): Path {
        val normalized = path.toAbsolutePath().normalize()
        require(normalized.startsWith(root)) { "$label escapes the repository boundary" }
        require(Files.isRegularFile(normalized, NOFOLLOW_LINKS) && !Files.isSymbolicLink(normalized)) {
            "$label is missing or is not a regular non-symlink file"
        }
        require(Files.size(normalized) in 1..MAX_INPUT_BYTES) { "$label has an invalid size" }
        return normalized
    }

    private fun verifyPluginPaths(root: Path, expectations: List<PluginExpectation>) {
        expectations.forEach { plugin ->
            plugin.configurationInputs.forEach { relative ->
                requireRegularInput(root.resolve(relative), root, "legacy plugin ${plugin.name} configuration input $relative")
            }
            plugin.mappingPaths.forEach { relative ->
                val path = root.resolve(relative).toAbsolutePath().normalize()
                require(path.startsWith(root) && path != root) {
                    "legacy plugin ${plugin.name} mapping path escapes the repository boundary"
                }
                require(!Files.isSymbolicLink(path)) {
                    "legacy plugin ${plugin.name} mapping path must not be a symbolic link"
                }
                if (Files.exists(path, NOFOLLOW_LINKS)) {
                    require(Files.isRegularFile(path, NOFOLLOW_LINKS)) {
                        "legacy plugin ${plugin.name} mapping path is not a regular file"
                    }
                }
            }
        }
    }

    private fun readUtf8(path: Path, label: String): String = try {
        Files.readString(path, Charsets.UTF_8)
    } catch (failure: Exception) {
        throw IllegalArgumentException("$label is unreadable UTF-8", failure)
    }

    private fun balancedBraceBlock(content: String, marker: String, label: String): String {
        val start = content.indexOf(marker)
        require(start >= 0 && content.indexOf(marker, start + marker.length) < 0) {
            "$label start marker must appear exactly once"
        }
        val brace = content.indexOf('{', start)
        require(brace >= 0) { "$label opening brace is missing" }
        var depth = 0
        for (index in brace until content.length) {
            when (content[index]) {
                '{' -> depth++
                '}' -> {
                    depth--
                    if (depth == 0) return content.substring(start, index + 1)
                }
            }
        }
        throw IllegalArgumentException("$label block is unterminated")
    }

    private fun allPositions(content: String, value: String): List<Int> = buildList {
        require(value.isNotEmpty()) { "legacy plugin exact line must not be empty" }
        var from = 0
        while (true) {
            val index = content.indexOf(value, from)
            if (index < 0) return@buildList
            add(index)
            from = index + value.length
        }
    }

    private fun artifactHasVersion(artifact: String, version: String): Boolean =
        Regex("(?:^|[-_.])${Regex.escape(version)}(?:[-_.]|\\.jar${'$'})").containsMatchIn(artifact)

    private fun Map<String, Any?>.map(key: String): Map<String, Any?> =
        this[key].asStringMap("legacy plugin baseline field $key")

    private fun Map<String, Any?>.string(key: String): String =
        (this[key] as? String)?.takeIf(String::isNotBlank)
            ?: throw IllegalArgumentException("legacy plugin baseline field $key is missing")

    private fun Map<String, Any?>.number(key: String): Number =
        this[key] as? Number ?: throw IllegalArgumentException("legacy plugin baseline field $key is missing")

    private fun Map<String, Any?>.sha256(key: String): String = string(key).also { value ->
        require(value.matches(SHA256)) { "legacy plugin baseline field $key is not SHA-256" }
    }

    private fun Map<String, Any?>.stringList(key: String): List<String> {
        val values = this[key] as? List<*>
            ?: throw IllegalArgumentException("legacy plugin baseline field $key is missing")
        return values.mapIndexed { index, value ->
            (value as? String)?.takeIf(String::isNotBlank)
                ?: throw IllegalArgumentException("legacy plugin baseline field $key[$index] is invalid")
        }.also { require(it.distinct().size == it.size) { "legacy plugin baseline field $key has duplicates" } }
    }

    private fun Map<String, Any?>.objectList(key: String): List<Map<String, Any?>> {
        val values = this[key] as? List<*>
            ?: throw IllegalArgumentException("legacy plugin baseline field $key is missing")
        return values.mapIndexed { index, value -> value.asStringMap("legacy plugin baseline field $key[$index]") }
    }

    private fun Any?.asStringMap(label: String): Map<String, Any?> {
        val raw = this as? Map<*, *> ?: throw IllegalArgumentException("$label must be an object")
        require(raw.keys.all { it is String }) { "$label contains a non-string key" }
        @Suppress("UNCHECKED_CAST")
        return raw as Map<String, Any?>
    }

    private data class PluginExpectation(
        val name: String,
        val pluginId: String,
        val expectedVersion: String,
        val implementationClass: String,
        val jarSha256: String,
        val extensionName: String,
        val extensionClass: String,
        val taskNames: List<String>,
        val taskClasses: List<String>,
        val configurationInputs: List<String>,
        val mappingPaths: List<String>,
        val frozenRegions: List<String>,
        val versionSources: List<String>,
    )

    private const val MAX_INPUT_BYTES = 4L * 1024 * 1024
    private val SHA256 = Regex("[0-9a-f]{64}")
    private val PLUGIN_ID = Regex("id\\(\"[^\"]+\"\\)")
    private val REQUIRED_BASELINE_KEYS = setOf(
        "schemaVersion", "capture", "frozenRegions", "versionSources", "plugins",
    )
    private val CAPTURE_KEYS = setOf(
        "hashAlgorithm", "encoding", "lineEndings", "regionBoundary", "sourceProvenance", "regions",
    )
    private val SOURCE_PROVENANCE_KEYS = setOf("path", "sourceRevision", "sha256")
    private val PLUGIN_KEYS = setOf(
        "name", "pluginId", "expectedVersion", "implementationClass", "jarSha256", "extensionName",
        "extensionClass", "taskNames", "taskClasses", "configurationInputs", "mappingPaths", "frozenRegions",
        "versionSources",
    )
}
