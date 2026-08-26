package com.holin.android.hardening.state

import java.nio.file.Path
import java.security.SecureRandom

const val STATE_SCHEMA_VERSION: Int = 2
const val LEGACY_STATE_SCHEMA_VERSION: Int = 1

data class StateCoordinates(
    val projectKey: String,
    val variant: String,
    val namespace: String,
    val applicationId: String,
    val configurationSha256: String,
)

enum class LineageReason { FIRST_BUILD, REUSED_CURRENT, MISSING_CURRENT, CORRUPT_CURRENT, IDENTITY_MISMATCH }

data class StateIdentity(
    val schemaVersion: Int,
    val projectKey: String,
    val variant: String,
    val namespace: String,
    val applicationId: String,
    val configurationSha256: String,
    val lineageId: String,
    val generation: Long,
    val seedHash: String,
    val payloadHashes: Map<String, String>,
    val lineageReset: Boolean,
    val derivationMode: SeedDerivationMode = SeedDerivationMode.SECURE_RANDOM,
    val fixedSeedSha256: String? = null,
)

data class SnapshotManifest(
    val schemaVersion: Int,
    val identity: StateIdentity,
    val lineageReason: LineageReason,
    val contentSaltSha256: String,
    val aabSha256: String? = null,
)

data class ActivePointer(
    val schemaVersion: Int,
    val generation: Long,
    val snapshotId: String,
    val payloadSha256: String,
)

fun interface EntropySource {
    fun nextBytes(purpose: String, size: Int): ByteArray
}

object SecureEntropySource : EntropySource {
    private val random = SecureRandom()
    override fun nextBytes(purpose: String, size: Int): ByteArray = ByteArray(size).also(random::nextBytes)
}

data class PrepareRequest @JvmOverloads constructor(
    val root: Path,
    val coordinates: StateCoordinates,
    val outputDirectory: Path,
    val contentSaltSha256: String,
    val reusePrevious: Boolean,
    val keepHistory: Boolean,
    val quarantineInvalid: Boolean,
    val reproducibility: StateReproducibility = StateReproducibility.secureRandom(),
)

data class PreparedState(
    val root: Path,
    val coordinates: StateCoordinates,
    val preparedDirectory: Path,
    val identity: StateIdentity,
    val reason: LineageReason,
    val expectedGeneration: Long,
    val expectedPayloadSha256: String?,
    val contentSaltSha256: String,
    val quarantinedDirectory: Path?,
    val keepHistory: Boolean,
)

data class ArchiveMappingVerificationEvidence(
    val hardenedAab: Path,
    val schema2PassingReport: Path,
)

data class ArchiveRequest @JvmOverloads constructor(
    val preparedState: PreparedState,
    val versionCode: Int,
    val aabSha256: String,
    val mappingVerificationEvidence: ArchiveMappingVerificationEvidence? = null,
)

data class ArchiveResult(
    val historyDirectory: Path,
    val snapshotDirectory: Path,
    val activePointer: ActivePointer,
)

data class StateConfigurationMigrationRequest(
    val root: Path,
    val targetCoordinates: StateCoordinates,
    val expected: PortableStateIdentityMigration,
)

enum class StateMigrationStatus { MIGRATED, ALREADY_MIGRATED }

data class StateConfigurationMigrationResult(
    val status: StateMigrationStatus,
    val activePointer: ActivePointer,
)

class GenerationConflictException(message: String) : IllegalStateException(message)
