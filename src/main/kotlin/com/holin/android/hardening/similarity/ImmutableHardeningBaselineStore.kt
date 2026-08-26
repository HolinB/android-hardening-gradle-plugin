package com.holin.android.hardening.similarity

import com.holin.android.hardening.state.AtomicFiles
import com.holin.android.hardening.state.PortableBaselineIdentityMigration
import com.holin.android.hardening.state.SafeStateFile
import com.holin.android.hardening.state.Sha256
import com.holin.android.hardening.state.StrictJson
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE
import java.util.UUID

data class HardeningBaselineCaptureRequest(
    val projectKey: String,
    val variant: String,
    val ordinaryAab: Path,
    val hardenedAab: Path,
    val ordinaryUniversalApk: Path,
    val hardenedUniversalApk: Path,
    val scorerVersion: String,
    val ownershipSha256: String,
    val configurationSha256: String,
    val report: SimilarityReport,
)

data class HardeningBaselineExpectation(
    val projectKey: String,
    val variant: String,
    val scorerVersion: String,
    val ownershipSha256: String,
    val configurationSha256: String,
)

data class HardeningBaseline(
    val root: Path,
    val report: SimilarityReport,
)

data class HardeningBaselineArtifacts(
    val ordinaryAab: Path,
    val hardenedAab: Path,
    val ordinaryUniversalApk: Path,
    val hardenedUniversalApk: Path,
)

data class HardeningBaselineOwnershipReevaluation(
    val root: Path,
    val artifacts: HardeningBaselineArtifacts,
    val storedReport: SimilarityReport,
)

enum class BaselineMigrationStatus { MIGRATED, ALREADY_MIGRATED }

data class HardeningBaselineMigrationResult(
    val status: BaselineMigrationStatus,
    val root: Path,
)

class ImmutableHardeningBaselineStore(
    repositoryRoot: Path,
    baselineDirectory: Path,
) {
    private val repositoryRoot = repositoryRoot.toAbsolutePath().normalize()
    private val baselineDirectory = baselineDirectory.toAbsolutePath().normalize()

    init {
        require(this.baselineDirectory.startsWith(this.repositoryRoot) && this.baselineDirectory != this.repositoryRoot) {
            "hardening baseline directory must stay below the repository root"
        }
    }

    fun capture(request: HardeningBaselineCaptureRequest): HardeningBaseline {
        validateIdentity(request.projectKey, request.variant)
        validateDigest(request.ownershipSha256, "ownership")
        validateDigest(request.configurationSha256, "configuration")
        require(request.scorerVersion == OwnedArtifactSimilarityScorerV1.SCORER_VERSION) {
            "unexpected hardening baseline scorer ${request.scorerVersion}"
        }
        val sources = artifactPaths(
            request.ordinaryAab,
            request.hardenedAab,
            request.ordinaryUniversalApk,
            request.hardenedUniversalApk,
        )
        sources.values.forEach(::requireRegularFile)
        validateReport(request.report, request.scorerVersion, sources)

        val target = baselineRoot(request.projectKey, request.variant)
        requireSafeDirectories(requireNotNull(target.parent), createMissing = true)
        require(!Files.exists(target, NOFOLLOW_LINKS)) {
            "hardening baseline already exists and is immutable: $target"
        }
        val staging = target.resolveSibling(".v1.tmp-${UUID.randomUUID()}")
        Files.createDirectory(staging)
        try {
            sources.forEach { (name, source) -> copyNoFollow(source, staging.resolve(name)) }
            val copied = artifactPaths(
                staging.resolve(ORDINARY_AAB),
                staging.resolve(HARDENED_AAB),
                staging.resolve(ORDINARY_APK),
                staging.resolve(HARDENED_APK),
            )
            writeNew(
                staging.resolve(BASELINE_JSON),
                BaselineMetadataCodec.encode(
                    BaselineMetadata(
                        scorerVersion = request.scorerVersion,
                        ownershipSha256 = request.ownershipSha256,
                        configurationSha256 = request.configurationSha256,
                        artifactHashes = copied.mapValues { (_, path) -> Sha256.file(path) },
                        artifactSizes = copied.mapValues { (_, path) -> Files.size(path) },
                        report = request.report,
                    ),
                ).toByteArray(Charsets.UTF_8),
            )
            AtomicFiles().publishDirectory(staging, target)
        } finally {
            deleteOwnedStaging(staging)
        }
        return load(
            HardeningBaselineExpectation(
                request.projectKey,
                request.variant,
                request.scorerVersion,
                request.ownershipSha256,
                request.configurationSha256,
            ),
        )
    }

    fun load(expectation: HardeningBaselineExpectation): HardeningBaseline {
        val verified = loadVerified(expectation, requireCurrentOwnership = true)
        return HardeningBaseline(verified.root, verified.metadata.report)
    }

    fun loadForOwnershipReevaluation(
        expectation: HardeningBaselineExpectation,
    ): HardeningBaselineOwnershipReevaluation {
        val verified = loadVerified(expectation, requireCurrentOwnership = false)
        return HardeningBaselineOwnershipReevaluation(
            root = verified.root,
            artifacts = HardeningBaselineArtifacts(
                ordinaryAab = verified.artifacts.getValue(ORDINARY_AAB),
                hardenedAab = verified.artifacts.getValue(HARDENED_AAB),
                ordinaryUniversalApk = verified.artifacts.getValue(ORDINARY_APK),
                hardenedUniversalApk = verified.artifacts.getValue(HARDENED_APK),
            ),
            storedReport = verified.metadata.report,
        )
    }

    fun migrateLegacyV1(
        projectKey: String,
        variant: String,
        targetConfigurationSha256: String,
        expected: PortableBaselineIdentityMigration,
    ): HardeningBaselineMigrationResult {
        validateIdentity(projectKey, variant)
        validateDigest(targetConfigurationSha256, "migration target configuration")
        require(expected.toConfigurationSha256 == targetConfigurationSha256) {
            "baseline migration target configuration differs from its descriptor"
        }
        validateDigest(expected.ownershipSha256, "migration ownership")
        validateDigest(expected.fromConfigurationSha256, "migration source configuration")
        validateDigest(expected.toConfigurationSha256, "migration descriptor target configuration")
        validateDigest(expected.legacyPayloadSha256, "migration legacy payload")
        val variantRoot = variantRoot(projectKey, variant)
        requireSafeDirectories(variantRoot, false)
        val activePath = variantRoot.resolve(ACTIVE_JSON)
        if (Files.exists(activePath, NOFOLLOW_LINKS)) {
            val active = readActivePointer(activePath)
            require(active.configurationSha256 == targetConfigurationSha256) {
                "active hardening baseline configuration differs from the migration target"
            }
            val selected = resolveActiveRoot(variantRoot, active)
            loadVerified(
                HardeningBaselineExpectation(
                    projectKey,
                    variant,
                    expected.scorerVersion,
                    expected.ownershipSha256,
                    targetConfigurationSha256,
                ),
                true,
            )
            return HardeningBaselineMigrationResult(BaselineMigrationStatus.ALREADY_MIGRATED, selected)
        }

        val legacy = loadVerified(
            HardeningBaselineExpectation(
                projectKey,
                variant,
                expected.scorerVersion,
                expected.ownershipSha256,
                expected.fromConfigurationSha256,
            ),
            true,
        )
        require(Sha256.canonicalPayload(legacy.root) == expected.legacyPayloadSha256) {
            "legacy hardening baseline payload differs from its migration descriptor"
        }
        val versions = variantRoot.resolve(VERSIONS_DIRECTORY)
        requireSafeDirectories(versions, true)
        val stage = versions.resolve(".tmp-${targetConfigurationSha256}-${UUID.randomUUID()}")
        Files.createDirectory(stage)
        try {
            REQUIRED_ARTIFACT_NAMES.forEach { name ->
                copyNoFollow(legacy.root.resolve(name), stage.resolve(name))
            }
            writeNew(
                stage.resolve(BASELINE_JSON),
                BaselineMetadataCodec.encode(
                    legacy.metadata.copy(configurationSha256 = targetConfigurationSha256),
                ).toByteArray(Charsets.UTF_8),
            )
            val target = versions.resolve(targetConfigurationSha256)
            if (Files.exists(target, NOFOLLOW_LINKS)) {
                require(Sha256.canonicalPayload(target) == Sha256.canonicalPayload(stage)) {
                    "immutable hardening baseline migration target already contains different bytes"
                }
                deleteOwnedStaging(stage)
            } else {
                AtomicFiles().publishDirectory(stage, target)
            }
            val pointer = BaselineActivePointer(
                1,
                targetConfigurationSha256,
                "$VERSIONS_DIRECTORY/$targetConfigurationSha256",
                Sha256.canonicalPayload(target),
            )
            AtomicFiles().replace(
                activePath,
                BaselineActivePointerCodec.encode(pointer).toByteArray(Charsets.UTF_8),
            )
            loadVerified(
                HardeningBaselineExpectation(
                    projectKey,
                    variant,
                    expected.scorerVersion,
                    expected.ownershipSha256,
                    targetConfigurationSha256,
                ),
                true,
            )
            return HardeningBaselineMigrationResult(BaselineMigrationStatus.MIGRATED, target)
        } finally {
            deleteOwnedStaging(stage)
        }
    }

    private fun loadVerified(
        expectation: HardeningBaselineExpectation,
        requireCurrentOwnership: Boolean,
    ): VerifiedBaseline {
        validateIdentity(expectation.projectKey, expectation.variant)
        validateDigest(expectation.ownershipSha256, "ownership")
        validateDigest(expectation.configurationSha256, "configuration")
        val variantRoot = variantRoot(expectation.projectKey, expectation.variant)
        requireSafeDirectories(variantRoot, false)
        val activePath = variantRoot.resolve(ACTIVE_JSON)
        val root = if (Files.exists(activePath, NOFOLLOW_LINKS)) {
            val active = readActivePointer(activePath)
            require(active.configurationSha256 == expectation.configurationSha256) {
                "active hardening baseline configuration mismatch"
            }
            resolveActiveRoot(variantRoot, active)
        } else {
            baselineRoot(expectation.projectKey, expectation.variant)
        }
        requireSafeDirectories(root, createMissing = false)
        val entries = Files.list(root).use { paths -> paths.toList() }
        require(entries.mapTo(linkedSetOf()) { it.fileName.toString() } == REQUIRED_FILES) {
            "hardening baseline must contain exactly $REQUIRED_FILES"
        }
        entries.forEach(::requireRegularFile)
        val metadata = BaselineMetadataCodec.decode(
            SafeStateFile.readUtf8(root.resolve(BASELINE_JSON), MAX_METADATA_BYTES),
        )
        validateDigest(metadata.ownershipSha256, "stored ownership")
        validateDigest(metadata.configurationSha256, "stored configuration")
        require(metadata.scorerVersion == expectation.scorerVersion) { "hardening baseline scorer mismatch" }
        if (requireCurrentOwnership) {
            require(metadata.ownershipSha256 == expectation.ownershipSha256) {
                "hardening baseline ownership mismatch"
            }
        }
        require(metadata.configurationSha256 == expectation.configurationSha256) { "hardening baseline configuration mismatch" }
        val artifacts = artifactPaths(
            root.resolve(ORDINARY_AAB),
            root.resolve(HARDENED_AAB),
            root.resolve(ORDINARY_APK),
            root.resolve(HARDENED_APK),
        )
        artifacts.forEach { (name, path) ->
            require(Sha256.file(path) == metadata.artifactHashes.getValue(name)) {
                "hardening baseline artifact hash mismatch for $name"
            }
            require(Files.size(path) == metadata.artifactSizes.getValue(name)) {
                "hardening baseline artifact size mismatch for $name"
            }
        }
        validateReport(metadata.report, metadata.scorerVersion, artifacts)
        return VerifiedBaseline(root, artifacts, metadata)
    }

    private fun baselineRoot(projectKey: String, variant: String): Path =
        baselineDirectory.resolve(projectKey).resolve(variant).resolve(VERSION_DIRECTORY).normalize()

    private fun variantRoot(projectKey: String, variant: String): Path =
        baselineDirectory.resolve(projectKey).resolve(variant).normalize()

    private fun readActivePointer(path: Path): BaselineActivePointer {
        requireRegularFile(path)
        return BaselineActivePointerCodec.decode(SafeStateFile.readUtf8(path, MAX_ACTIVE_BYTES))
    }

    private fun resolveActiveRoot(variantRoot: Path, pointer: BaselineActivePointer): Path {
        val selected = variantRoot.resolve(pointer.directory).normalize()
        require(selected.startsWith(variantRoot) && selected != variantRoot) {
            "active hardening baseline path escapes its variant root"
        }
        requireSafeDirectories(selected, false)
        require(Sha256.canonicalPayload(selected) == pointer.payloadSha256) {
            "active hardening baseline payload hash mismatch"
        }
        return selected
    }

    private fun requireSafeDirectories(path: Path, createMissing: Boolean) {
        require(path.startsWith(repositoryRoot)) { "hardening baseline path escaped the repository root" }
        require(Files.isDirectory(repositoryRoot, NOFOLLOW_LINKS) && !Files.isSymbolicLink(repositoryRoot)) {
            "hardening baseline repository root is unsafe"
        }
        var current = repositoryRoot
        repositoryRoot.relativize(path).forEach { component ->
            current = current.resolve(component)
            if (!Files.exists(current, NOFOLLOW_LINKS)) {
                require(createMissing) { "hardening baseline directory is missing: $current" }
                Files.createDirectory(current)
            }
            require(Files.isDirectory(current, NOFOLLOW_LINKS) && !Files.isSymbolicLink(current)) {
                "symlink or non-directory is not allowed in hardening baseline path: $current"
            }
        }
    }

    private fun requireRegularFile(path: Path) {
        require(Files.isRegularFile(path, NOFOLLOW_LINKS) && !Files.isSymbolicLink(path)) {
            "hardening baseline artifact is missing or unsafe: $path"
        }
    }

    private fun copyNoFollow(source: Path, target: Path) {
        FileChannel.open(source, READ, NOFOLLOW_LINKS).use { input ->
            FileChannel.open(target, CREATE_NEW, WRITE, NOFOLLOW_LINKS).use { output ->
                var position = 0L
                while (position < input.size()) position += input.transferTo(position, input.size() - position, output)
                output.force(true)
            }
        }
    }

    private fun writeNew(path: Path, bytes: ByteArray) {
        FileChannel.open(path, CREATE_NEW, WRITE, NOFOLLOW_LINKS).use { channel ->
            val buffer = ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) channel.write(buffer)
            channel.force(true)
        }
    }

    private fun deleteOwnedStaging(staging: Path) {
        if (!Files.exists(staging, NOFOLLOW_LINKS)) return
        Files.walk(staging).use { paths ->
            paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    private fun validateIdentity(projectKey: String, variant: String) {
        require(projectKey.isNotBlank()) { "hardening baseline project key must not be blank" }
        require(variant.isNotBlank()) { "hardening baseline variant must not be blank" }
    }

    private fun validateDigest(value: String, label: String) {
        require(SHA_256.matches(value)) { "hardening baseline $label digest must be lowercase SHA-256" }
    }

    private fun validateReport(report: SimilarityReport, scorerVersion: String, artifacts: Map<String, Path>) {
        require(report.scorerVersion == scorerVersion) { "hardening baseline report scorer mismatch" }
        require(report.comparisonMode == ArtifactComparisonMode.DUAL_AAB_APK) {
            "hardening baseline report must analyze AAB and universal APK artifacts"
        }
        require(report.ordinaryAabSha256 == Sha256.file(artifacts.getValue(ORDINARY_AAB))) {
            "hardening baseline report ordinary AAB hash mismatch"
        }
        require(report.hardenedAabSha256 == Sha256.file(artifacts.getValue(HARDENED_AAB))) {
            "hardening baseline report hardened AAB hash mismatch"
        }
        require(report.ordinaryUniversalApkSha256 == Sha256.file(artifacts.getValue(ORDINARY_APK))) {
            "hardening baseline report ordinary APK hash mismatch"
        }
        require(report.hardenedUniversalApkSha256 == Sha256.file(artifacts.getValue(HARDENED_APK))) {
            "hardening baseline report hardened APK hash mismatch"
        }
        require(report.ordinaryAabSize == Files.size(artifacts.getValue(ORDINARY_AAB)) &&
            report.hardenedAabSize == Files.size(artifacts.getValue(HARDENED_AAB)) &&
            report.ordinaryUniversalApkSize == Files.size(artifacts.getValue(ORDINARY_APK)) &&
            report.hardenedUniversalApkSize == Files.size(artifacts.getValue(HARDENED_APK))) {
            "hardening baseline report artifact size mismatch"
        }
    }

    private fun artifactPaths(
        ordinaryAab: Path,
        hardenedAab: Path,
        ordinaryApk: Path,
        hardenedApk: Path,
    ): Map<String, Path> = linkedMapOf(
        ORDINARY_AAB to ordinaryAab,
        HARDENED_AAB to hardenedAab,
        ORDINARY_APK to ordinaryApk,
        HARDENED_APK to hardenedApk,
    )

    companion object {
        const val ORDINARY_AAB = "ordinary.aab"
        const val HARDENED_AAB = "hardened.aab"
        const val ORDINARY_APK = "ordinary-universal.apk"
        const val HARDENED_APK = "hardened-universal.apk"
        const val BASELINE_JSON = "baseline.json"
        private const val VERSION_DIRECTORY = "v1"
        private const val VERSIONS_DIRECTORY = "versions"
        private const val ACTIVE_JSON = "active.json"
        private const val MAX_ACTIVE_BYTES = 16L * 1024L
        private const val MAX_METADATA_BYTES = 1024L * 1024L
        private val REQUIRED_FILES = linkedSetOf(ORDINARY_AAB, HARDENED_AAB, ORDINARY_APK, HARDENED_APK, BASELINE_JSON)
        private val SHA_256 = Regex("[0-9a-f]{64}")
    }

    private data class VerifiedBaseline(
        val root: Path,
        val artifacts: Map<String, Path>,
        val metadata: BaselineMetadata,
    )
}

private data class BaselineActivePointer(
    val schemaVersion: Int,
    val configurationSha256: String,
    val directory: String,
    val payloadSha256: String,
)

private object BaselineActivePointerCodec {
    fun encode(pointer: BaselineActivePointer): String =
        "{\"schemaVersion\":1,\"configurationSha256\":${JsonOutput.toJson(pointer.configurationSha256)}," +
            "\"directory\":${JsonOutput.toJson(pointer.directory)}," +
            "\"payloadSha256\":${JsonOutput.toJson(pointer.payloadSha256)}}\n"

    fun decode(text: String): BaselineActivePointer {
        StrictJson.validateDocument(text)
        val root = JsonSlurper().parseText(text) as? Map<*, *>
            ?: throw IllegalArgumentException("hardening baseline active pointer must be an object")
        require(root.keys == KEYS) { "hardening baseline active pointer keys are invalid" }
        val pointer = BaselineActivePointer(
            (root["schemaVersion"] as? Number)?.toInt()
                ?: throw IllegalArgumentException("hardening baseline active schemaVersion is invalid"),
            root["configurationSha256"] as? String
                ?: throw IllegalArgumentException("hardening baseline active configuration is invalid"),
            root["directory"] as? String
                ?: throw IllegalArgumentException("hardening baseline active directory is invalid"),
            root["payloadSha256"] as? String
                ?: throw IllegalArgumentException("hardening baseline active payload is invalid"),
        )
        require(pointer.schemaVersion == 1) { "unsupported hardening baseline active schema" }
        require(SHA_256.matches(pointer.configurationSha256) && SHA_256.matches(pointer.payloadSha256)) {
            "hardening baseline active hashes are invalid"
        }
        require(pointer.directory == "versions/${pointer.configurationSha256}") {
            "hardening baseline active directory does not match its configuration"
        }
        return pointer
    }

    private val KEYS = setOf("schemaVersion", "configurationSha256", "directory", "payloadSha256")
    private val SHA_256 = Regex("[0-9a-f]{64}")
}

private data class BaselineMetadata(
    val scorerVersion: String,
    val ownershipSha256: String,
    val configurationSha256: String,
    val artifactHashes: Map<String, String>,
    val artifactSizes: Map<String, Long>,
    val report: SimilarityReport,
)

private object BaselineMetadataCodec {
    fun encode(metadata: BaselineMetadata): String = buildString {
        append("{\"schemaVersion\":1")
        append(",\"scorerVersion\":").append(JsonOutput.toJson(metadata.scorerVersion))
        append(",\"ownershipSha256\":").append(JsonOutput.toJson(metadata.ownershipSha256))
        append(",\"configurationSha256\":").append(JsonOutput.toJson(metadata.configurationSha256))
        append(",\"artifacts\":{")
        ImmutableHardeningBaselineStore.REQUIRED_ARTIFACT_NAMES.forEachIndexed { index, name ->
            if (index > 0) append(',')
            append(JsonOutput.toJson(name)).append(":{\"sha256\":")
                .append(JsonOutput.toJson(metadata.artifactHashes.getValue(name)))
                .append(",\"size\":").append(metadata.artifactSizes.getValue(name)).append('}')
        }
        append("},\"similarityReportJson\":")
            .append(JsonOutput.toJson(SimilarityReportCodec.encode(metadata.report)))
        append("}\n")
    }

    fun decode(text: String): BaselineMetadata {
        StrictJson.validateDocument(text)
        val root = JsonSlurper().parseText(text) as? Map<*, *>
            ?: throw IllegalArgumentException("hardening baseline metadata must be an object")
        require(root.keys == ROOT_KEYS) { "hardening baseline metadata keys are invalid" }
        require((root["schemaVersion"] as? Number)?.toInt() == 1) { "unsupported hardening baseline schema" }
        val artifacts = root["artifacts"] as? Map<*, *>
            ?: throw IllegalArgumentException("hardening baseline artifacts must be an object")
        require(artifacts.keys == ImmutableHardeningBaselineStore.REQUIRED_ARTIFACT_NAMES.toSet()) {
            "hardening baseline artifact metadata keys are invalid"
        }
        val hashes = linkedMapOf<String, String>()
        val sizes = linkedMapOf<String, Long>()
        ImmutableHardeningBaselineStore.REQUIRED_ARTIFACT_NAMES.forEach { name ->
            val artifact = artifacts[name] as? Map<*, *>
                ?: throw IllegalArgumentException("hardening baseline artifact $name must be an object")
            require(artifact.keys == ARTIFACT_KEYS) { "hardening baseline artifact $name keys are invalid" }
            hashes[name] = artifact["sha256"] as? String
                ?: throw IllegalArgumentException("hardening baseline artifact $name hash is invalid")
            sizes[name] = (artifact["size"] as? Number)?.toLong()
                ?: throw IllegalArgumentException("hardening baseline artifact $name size is invalid")
        }
        return BaselineMetadata(
            scorerVersion = root["scorerVersion"] as? String
                ?: throw IllegalArgumentException("hardening baseline scorer is invalid"),
            ownershipSha256 = root["ownershipSha256"] as? String
                ?: throw IllegalArgumentException("hardening baseline ownership digest is invalid"),
            configurationSha256 = root["configurationSha256"] as? String
                ?: throw IllegalArgumentException("hardening baseline configuration digest is invalid"),
            artifactHashes = hashes,
            artifactSizes = sizes,
            report = SimilarityReportCodec.decode(
                root["similarityReportJson"] as? String
                    ?: throw IllegalArgumentException("hardening baseline similarity report is invalid"),
            ),
        )
    }

    private val ROOT_KEYS = setOf(
        "schemaVersion", "scorerVersion", "ownershipSha256", "configurationSha256", "artifacts", "similarityReportJson",
    )
    private val ARTIFACT_KEYS = setOf("sha256", "size")
}

internal val ImmutableHardeningBaselineStore.Companion.REQUIRED_ARTIFACT_NAMES: List<String>
    get() = listOf(ORDINARY_AAB, HARDENED_AAB, ORDINARY_APK, HARDENED_APK)
