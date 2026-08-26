package com.holin.android.hardening.artifact

import com.holin.android.hardening.HardeningNames
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardOpenOption.READ
import java.util.UUID

/**
 * Publishes a stable artifact set around the state CAS callback. Existing
 * outputs are restored when the callback fails, while the caller holds the
 * cross-process hardening lock.
 */
class VerifiedArtifactPublisher internal constructor(
    private val cleanupDeleteIfExists: (Path) -> Unit,
) {
    constructor() : this({ path ->
        Files.deleteIfExists(path)
        Unit
    })

    fun <T> publish(
        sourceBundle: Path,
        sourceReport: Path,
        targetBundle: Path,
        targetReport: Path,
        commit: () -> T,
    ): T = publish(
        publications = listOf(
            Publication(sourceBundle, targetBundle),
            Publication(sourceReport, targetReport),
        ),
        commit = commit,
    )

    fun <T> publish(
        publications: List<Publication>,
        commit: () -> T,
    ): T {
        require(publications.isNotEmpty()) { "hardening artifact publication set must not be empty" }
        val normalizedTargets = publications.map { publication ->
            publication.target.toAbsolutePath().normalize()
        }
        require(normalizedTargets.distinct().size == normalizedTargets.size) {
            "hardening artifact publication targets must be distinct"
        }
        publications.forEach { publication ->
            requireSafeSource(publication.source)
            require(
                publication.source.toAbsolutePath().normalize() != publication.target.toAbsolutePath().normalize(),
            ) { "hardening artifact source and target must be distinct" }
            requireSafeTarget(publication.target)
            Files.createDirectories(requireNotNull(publication.target.parent))
        }

        val nonce = UUID.randomUUID().toString()
        val states = publications.map { publication -> PublicationState(publication, nonce) }
        val targetDirectories = states.mapTo(linkedSetOf()) { state ->
            requireNotNull(state.publication.target.parent)
        }
        var committed = false
        try {
            states.forEach { state -> copyForced(state.publication.source, state.staged) }
            states.forEach { state ->
                if (Files.exists(state.publication.target, NOFOLLOW_LINKS)) {
                    Files.move(state.publication.target, state.backup, ATOMIC_MOVE)
                    state.backedUp = true
                }
            }
            states.forEach { state ->
                Files.move(state.staged, state.publication.target, ATOMIC_MOVE)
                state.published = true
            }
            targetDirectories.forEach(::forceDirectory)

            val result = commit()
            committed = true
            states.forEach { state -> cleanupBestEffort(state.backup) }
            targetDirectories.forEach(::forceDirectory)
            return result
        } catch (failure: Throwable) {
            if (committed) throw failure
            val rollbackFailures = mutableListOf<Throwable>()
            states.asReversed().forEach { state ->
                if (state.published) {
                    runCatching { Files.deleteIfExists(state.publication.target) }
                        .exceptionOrNull()
                        ?.let(rollbackFailures::add)
                }
                if (state.backedUp) {
                    runCatching { Files.move(state.backup, state.publication.target, ATOMIC_MOVE) }
                        .exceptionOrNull()
                        ?.let(rollbackFailures::add)
                }
            }
            if (rollbackFailures.isNotEmpty()) {
                rollbackFailures.forEach(failure::addSuppressed)
                throw IllegalStateException("hardening artifact publication rollback failed", failure)
            }
            throw failure
        } finally {
            states.forEach { state -> cleanupBestEffort(state.staged) }
            if (committed) {
                states.forEach { state -> cleanupBestEffort(state.backup) }
            }
        }
    }

    data class Publication(val source: Path, val target: Path)

    private class PublicationState(
        val publication: Publication,
        nonce: String,
    ) {
        val staged: Path = sibling(publication.target, "new", nonce)
        val backup: Path = sibling(publication.target, "backup", nonce)
        var backedUp: Boolean = false
        var published: Boolean = false
    }

    private fun requireSafeSource(path: Path) {
        require(Files.isRegularFile(path, NOFOLLOW_LINKS) && !Files.isSymbolicLink(path)) {
            "verified hardening artifact source is missing or unsafe"
        }
    }

    private fun requireSafeTarget(path: Path) {
        require(!Files.exists(path, NOFOLLOW_LINKS) ||
            (Files.isRegularFile(path, NOFOLLOW_LINKS) && !Files.isSymbolicLink(path))
        ) { "hardening artifact target is unsafe" }
    }

    private companion object {
        fun sibling(target: Path, role: String, nonce: String): Path =
            target.resolveSibling(".hardening-tmp-${target.fileName}-$role-$nonce")
    }

    private fun copyForced(source: Path, target: Path) {
        Files.copy(source, target)
        FileChannel.open(target, READ).use { it.force(true) }
    }

    private fun forceDirectory(directory: Path) {
        runCatching { FileChannel.open(directory, READ).use { it.force(true) } }
    }

    private fun cleanupBestEffort(path: Path) {
        runCatching { cleanupDeleteIfExists(path) }
    }
}

data class BundleVerificationReport(
    val variant: String,
    val contentSaltSha256: String,
    val ordinaryAabSha256: String,
    val hardenedAabSha256: String,
    val signerCertificateSha256: String,
    val preservedEntryCount: Int,
    val bundletoolValidated: Boolean,
    val fixedSeedProvided: Boolean = false,
    val fixedSeedHash: String? = null,
)

object BundleVerificationReportCodec {
    fun encode(report: BundleVerificationReport): String {
        validate(report)
        return "{" +
            "\"schemaVersion\":1," +
            "\"variant\":\"${report.variant}\"," +
            "\"contentSaltSha256\":\"${report.contentSaltSha256}\"," +
            "\"ordinaryAabSha256\":\"${report.ordinaryAabSha256}\"," +
            "\"hardenedAabSha256\":\"${report.hardenedAabSha256}\"," +
            "\"signerCertificateSha256\":\"${report.signerCertificateSha256}\"," +
            "\"preservedEntryCount\":${report.preservedEntryCount}," +
            "\"bundletoolValidated\":${report.bundletoolValidated}," +
            "\"fixedSeedProvided\":${report.fixedSeedProvided}," +
            "\"fixedSeedHash\":${report.fixedSeedHash?.let { hash -> "\"$hash\"" } ?: "null"}}\n"
    }

    fun decode(text: String): BundleVerificationReport {
        val match = requireNotNull(FORMAT.matchEntire(text)) { "hardening bundle verification report is invalid" }
        val report = BundleVerificationReport(
            match.groupValues[1],
            match.groupValues[2],
            match.groupValues[3],
            match.groupValues[4],
            match.groupValues[5],
            match.groupValues[6].toIntOrNull()
                ?: throw IllegalArgumentException("hardening bundle verification report is invalid"),
            match.groupValues[7].toBooleanStrict(),
            match.groupValues[8].toBooleanStrict(),
            match.groupValues[9].takeIf(String::isNotEmpty),
        )
        validate(report)
        return report
    }

    private fun validate(report: BundleVerificationReport) {
        HardeningNames.requireVariant(report.variant)
        listOf(
            report.contentSaltSha256,
            report.ordinaryAabSha256,
            report.hardenedAabSha256,
            report.signerCertificateSha256,
        ).forEach { hash -> require(SHA_256.matches(hash)) { "hardening verification report contains an invalid SHA-256" } }
        require(report.preservedEntryCount >= 0) { "hardening verification report contains a negative entry count" }
        require(report.bundletoolValidated) { "hardening verification report did not pass bundletool" }
        require(report.fixedSeedProvided == (report.fixedSeedHash != null)) {
            "fixed seed hash must be present exactly when fixedSeedProvided is true"
        }
        report.fixedSeedHash?.let { hash ->
            require(SHA_256.matches(hash)) { "fixedSeedHash must be a lowercase SHA-256" }
        }
    }

    private val SHA_256 = Regex("[0-9a-f]{64}")
    private val FORMAT = Regex(
        "\\{\"schemaVersion\":1,\"variant\":\"([A-Za-z][A-Za-z0-9]*)\"," +
            "\"contentSaltSha256\":\"([0-9a-f]{64})\"," +
            "\"ordinaryAabSha256\":\"([0-9a-f]{64})\"," +
            "\"hardenedAabSha256\":\"([0-9a-f]{64})\"," +
            "\"signerCertificateSha256\":\"([0-9a-f]{64})\"," +
            "\"preservedEntryCount\":([0-9]+),\"bundletoolValidated\":(true|false)," +
            "\"fixedSeedProvided\":(true|false),\"fixedSeedHash\":(?:\"([0-9a-f]{64})\"|null)}\\n",
    )
}
