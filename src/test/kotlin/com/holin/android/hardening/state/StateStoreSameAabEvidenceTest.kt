package com.holin.android.hardening.state

import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile
import com.android.tools.smali.dexlib2.immutable.ImmutableField
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter
import com.android.tools.smali.dexlib2.writer.io.MemoryDataStore
import com.android.tools.smali.dexlib2.writer.pool.DexPool
import com.holin.android.hardening.verification.MappingContinuityVerifier
import com.holin.android.hardening.verification.MappingSymbolCounts
import com.holin.android.hardening.verification.MappingVerificationReport
import com.holin.android.hardening.verification.MappingVerificationReportCodec
import com.holin.android.hardening.verification.MappingVerificationStatus
import com.holin.android.hardening.verification.ParsedR8Mapping
import com.holin.android.hardening.verification.PotentialBeanFieldVerificationResult
import com.holin.android.hardening.verification.R8MappingParser
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class StateStoreSameAabEvidenceTest {
    @TempDir
    lateinit var temporary: Path

    @Test
    fun `removed-only same AAB mapping change advances current without changing history and repeats idempotently`() {
        val fixture = initialArchive("current-only-success")
        val historyBytes = fixture.archive.historyDirectory.readSnapshotBytes()
        val changed = fixture.prepare("changed", REMOVED_ONLY_MAPPING)
        val evidence = fixture.evidence(changed, fixture.previousMappingHash)

        val archived = fixture.store.archive(
            ArchiveRequest(changed, 42, fixture.aabSha256, evidence),
        )

        assertEquals(fixture.archive.historyDirectory, archived.historyDirectory)
        assertEquals(historyBytes, fixture.archive.historyDirectory.readSnapshotBytes())
        assertEquals(1, fixture.root.resolve("history").toFile().list()!!.size)
        assertEquals(fixture.archive.activePointer.generation + 1, archived.activePointer.generation)
        assertNotEquals(archived.historyDirectory, archived.snapshotDirectory)
        assertEquals(REMOVED_ONLY_MAPPING, archived.snapshotDirectory.resolve("mapping.txt").readText())

        val repeated = fixture.prepare("repeated", REMOVED_ONLY_MAPPING)
        val repeatedArchive = fixture.store.archive(ArchiveRequest(repeated, 42, fixture.aabSha256))

        assertEquals(archived.activePointer, repeatedArchive.activePointer)
        assertEquals(archived.snapshotDirectory, repeatedArchive.snapshotDirectory)
        assertEquals(historyBytes, fixture.archive.historyDirectory.readSnapshotBytes())
    }

    @Test
    fun `same AAB state change rejects missing schema 2 PASS evidence`() {
        val fixture = initialArchive("missing-evidence")
        val changed = fixture.prepare("changed", REMOVED_ONLY_MAPPING)

        val failure = assertFailsWith<IllegalArgumentException> {
            fixture.store.archive(ArchiveRequest(changed, 42, fixture.aabSha256))
        }

        assertContains(failure.message.orEmpty(), "schema-2 PASS evidence")
        assertEquals(fixture.archive.activePointer, fixture.store.readActivePointer(fixture.root))
    }

    @Test
    fun `same AAB state change rejects evidence bound to another active mapping`() {
        val fixture = initialArchive("mismatched-evidence")
        val changed = fixture.prepare("changed", REMOVED_ONLY_MAPPING)
        val evidence = fixture.evidence(changed, "9".repeat(64))

        val failure = assertFailsWith<IllegalArgumentException> {
            fixture.store.archive(ArchiveRequest(changed, 42, fixture.aabSha256, evidence))
        }

        assertContains(failure.message.orEmpty(), "active mapping")
        assertEquals(fixture.archive.activePointer, fixture.store.readActivePointer(fixture.root))
    }

    @Test
    fun `same AAB state change rejects forged PASS evidence when a present mapping changed`() {
        val fixture = initialArchive("forged-evidence")
        val changed = fixture.prepare("changed", PRESENT_FIELD_CHANGED_MAPPING)
        val evidence = fixture.evidence(changed, fixture.previousMappingHash, true)

        val failure = assertFailsWith<IllegalArgumentException> {
            fixture.store.archive(ArchiveRequest(changed, 42, fixture.aabSha256, evidence))
        }

        assertContains(failure.message.orEmpty(), "AAB-present FIELD mapping")
        assertEquals(fixture.archive.activePointer, fixture.store.readActivePointer(fixture.root))
    }

    private fun initialArchive(suffix: String): Fixture {
        val root = temporary.resolve(suffix).resolve("state")
        val aab = aab()
        val aabSha256 = Sha256.file(aab)
        val store = StateStore()
        val reproducibility = StateReproducibility.fixed(
            FixedSeedDerivation.seedSha256("same-aab-$suffix"),
            ReproducibilityContext("demo", "demoRelease", CONFIGURATION_SHA256),
        )
        val first = store.prepare(prepareRequest(root, temporary.resolve(suffix).resolve("first"), reproducibility))
        first.preparedDirectory.resolve("mapping.txt").writeText(PREVIOUS_MAPPING)
        val archive = store.archive(ArchiveRequest(first, 42, aabSha256))
        return Fixture(root, aab, aabSha256, reproducibility, store, archive, Sha256.file(archive.snapshotDirectory.resolve("mapping.txt")))
    }

    private fun prepareRequest(
        root: Path,
        output: Path,
        reproducibility: StateReproducibility,
    ): PrepareRequest = PrepareRequest(
        root,
        StateCoordinates(
            "demo",
            "demoRelease",
            "com.example.demo.match",
            "com.example.demo.match",
            CONFIGURATION_SHA256,
        ),
        output,
        CONTENT_SALT_SHA256,
        true,
        true,
        true,
        reproducibility,
    )

    private fun mapping(path: Path): ParsedR8Mapping = R8MappingParser().parse(path, null)

    private fun report(
        previousMappingSha256: String,
        candidateMapping: Path,
        aabSha256: String,
        fixedSeedSha256: String,
        forgePassingContinuity: Boolean,
    ): String {
        val previous = R8MappingParser().parse(PREVIOUS_MAPPING, null)
        val candidate = mapping(candidateMapping)
        val reportedCandidate = if (forgePassingContinuity) previous else candidate
        return MappingVerificationReportCodec.encode(
            MappingVerificationReport(
                "demoRelease",
                MappingVerificationStatus.PASS,
                "8.13.19",
                Sha256.hex(PREVIOUS_MAPPING.toByteArray(Charsets.UTF_8)),
                previousMappingSha256,
                Sha256.file(candidateMapping),
                Sha256.file(candidateMapping),
                aabSha256,
                "1".repeat(64),
                "2".repeat(64),
                "3".repeat(64),
                CONTENT_SALT_SHA256,
                "4".repeat(64),
                PotentialBeanFieldVerificationResult(1, mapOf(":app" to 1), 1, 1, 0, emptyList()),
                1,
                1,
                0,
                MappingSymbolCounts.from(previous),
                MappingSymbolCounts.from(reportedCandidate),
                MappingContinuityVerifier().verify(previous, reportedCandidate),
                "at a.b(HardeningSource:7)",
                listOf("at com.example.Present.run(Present.java:7)"),
                true,
                emptyList(),
                true,
                fixedSeedSha256,
            ),
        )
    }

    private fun aab(): Path = temporary.resolve("same-aab-${System.nanoTime()}.aab").also { path ->
        val method = ImmutableMethod(
            "La/b;",
            "d",
            emptyList<ImmutableMethodParameter>(),
            "V",
            AccessFlags.PUBLIC.value or AccessFlags.ABSTRACT.value,
            emptySet(),
            emptySet(),
            null,
        )
        val clazz = ImmutableClassDef(
            "La/b;",
            AccessFlags.PUBLIC.value,
            "Ljava/lang/Object;",
            emptyList(),
            null,
            emptySet(),
            listOf(ImmutableField("La/b;", "c", "I", AccessFlags.PUBLIC.value, null, emptySet(), emptySet())),
            listOf(method),
        )
        val store = MemoryDataStore()
        DexPool.writeTo(store, ImmutableDexFile(Opcodes.getDefault(), listOf(clazz)))
        ZipOutputStream(Files.newOutputStream(path)).use { output ->
            output.putNextEntry(ZipEntry("base/dex/classes.dex"))
            output.write(store.data)
            output.closeEntry()
        }
    }

    private fun Path.readSnapshotBytes(): Map<String, List<Byte>> = Files.list(this).use { entries ->
        entries.sorted().toList().associate { path -> path.fileName.toString() to path.readBytes().toList() }
    }

    private inner class Fixture(
        val root: Path,
        val aab: Path,
        val aabSha256: String,
        val reproducibility: StateReproducibility,
        val store: StateStore,
        val archive: ArchiveResult,
        val previousMappingHash: String,
    ) {
        fun prepare(suffix: String, mapping: String): PreparedState = store.prepare(
            prepareRequest(root, temporary.resolve(root.parent.fileName.toString()).resolve(suffix), reproducibility),
        ).also { prepared -> prepared.preparedDirectory.resolve("mapping.txt").writeText(mapping) }

        fun evidence(
            prepared: PreparedState,
            previousMappingSha256: String,
            forgePassingContinuity: Boolean = false,
        ): ArchiveMappingVerificationEvidence {
            val reportPath = prepared.preparedDirectory.resolve("mapping-verification.json")
            reportPath.writeText(
                report(
                    previousMappingSha256,
                    prepared.preparedDirectory.resolve("mapping.txt"),
                    aabSha256,
                    prepared.identity.fixedSeedSha256!!,
                    forgePassingContinuity,
                ),
            )
            return ArchiveMappingVerificationEvidence(aab, reportPath)
        }
    }

    private companion object {
        val CONFIGURATION_SHA256 = "b".repeat(64)
        val CONTENT_SALT_SHA256 = "c".repeat(64)
        val PREVIOUS_MAPPING = """
            # compiler: R8
            # compiler_version: 8.13.19
            com.example.Present -> a.b:
                int value -> c
                void run() -> d
            com.example.Removed -> r.s:
                int gone -> t
                void gone() -> u
        """.trimIndent() + "\n"
        val REMOVED_ONLY_MAPPING = """
            # compiler: R8
            # compiler_version: 8.13.19
            com.example.Present -> a.b:
                int value -> c
                void run() -> d
        """.trimIndent() + "\n"
        val PRESENT_FIELD_CHANGED_MAPPING = """
            # compiler: R8
            # compiler_version: 8.13.19
            com.example.Present -> a.b:
                int value -> x
                void run() -> d
        """.trimIndent() + "\n"
    }
}
