package com.holin.android.hardening.state

import com.holin.android.hardening.artifact.ArtifactPathBoundary
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.channels.OverlappingFileLockException
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.FileVisitResult
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.StandardOpenOption.CREATE
import java.nio.file.StandardOpenOption.WRITE

/** A lease owns only explicitly enumerated, per-invocation scratch paths. */
internal class HardeningScratchSession(
    buildDirectory: Path,
    repositoryRoot: Path,
    module: String,
    private val variant: String,
    private val invocation: String,
) : AutoCloseable {
    private val root = buildDirectory.toAbsolutePath().normalize()
    private val paths = ArtifactPathBoundary(root)
    private val identity = Sha256.hex((repositoryRoot.toAbsolutePath().normalize().toString() + "\n" + module + "\n" + variant).toByteArray())
    private val base = root.resolve("hardening/$variant")
    private val records = base.resolve(".cleanup")
    private val record = records.resolve(invocation)
    private val manifest = record.resolve("manifest.json")
    private val report = root.resolve("reports/hardening/$variant/cleanup-report.json")
    private val protected = linkedSetOf<String>()
    private val retained = arrayListOf<Map<String, String>>()
    private val failures = arrayListOf<Map<String, String>>()
    private var deletedFiles = 0L
    private var deletedDirectories = 0L
    private var deletedBytes = 0L
    private var leaseChannel: FileChannel? = null
    private var lease: FileLock? = null
    private var started = false
    private var closed = false
    val failureCount: Int get() = failures.size

    init {
        require(variant.matches(Regex("[A-Za-z0-9_-]+"))) { "unsafe cleanup variant" }
        require(invocation.matches(ID)) { "unsafe cleanup invocation" }
    }

    @Synchronized
    fun start() {
        check(!closed) { "cleanup session is closed" }
        if (started) return
        Files.createDirectories(root)
        withRegistryLock {
            recover()
            val leasePath = paths.prepareOutput(record.resolve("lease.lock"))
            require(!Files.exists(manifest, NOFOLLOW_LINKS)) { "cleanup invocation already exists" }
            leaseChannel = FileChannel.open(leasePath, CREATE, WRITE, NOFOLLOW_LINKS)
            lease = requireNotNull(leaseChannel!!.tryLock()) { "cleanup invocation is active" }
            entries(invocation).forEach { relative ->
                val candidate = paths.requireSafePath(root.resolve(relative))
                val emptyDirectory = Files.isDirectory(candidate, NOFOLLOW_LINKS) && Files.newDirectoryStream(candidate).use { !it.iterator().hasNext() }
                if (Files.exists(candidate, NOFOLLOW_LINKS) && !emptyDirectory) {
                    protected += relative
                    retained += row(relative, "PREEXISTING_UNOWNED_PATH")
                }
            }
            writeManifest()
            started = true
            discoverLegacy()
        }
    }

    @Synchronized
    fun retain(outputs: Collection<Path>) {
        start()
        val additions = outputs.mapNotNull { output ->
            val absolute = output.toAbsolutePath().normalize()
            if (absolute.startsWith(root) && absolute != root) {
                relative(absolute).takeIf { candidate ->
                    candidate !in protected && entries(invocation).any { isWithin(candidate, it) || isWithin(it, candidate) }
                }
            } else null
        }
        if (additions.isEmpty()) return
        withRegistryLock {
            protected += additions
            writeManifest()
        }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        if (!started) {
            releaseLease()
            return
        }
        try {
            withRegistryLock {
                cleanup(invocation, protected)
                releaseLease()
                retireRecord(record, invocation, protected)
                writeReport()
            }
        } finally {
            releaseLease()
        }
    }

    private fun recover() {
        if (!Files.isDirectory(records, NOFOLLOW_LINKS)) return
        paths.requireSafePath(records)
        Files.newDirectoryStream(records).use { directories ->
            directories.filter { it.fileName.toString().matches(ID) && it != record }.forEach { previous ->
                val previousId = previous.fileName.toString()
                try {
                    paths.requireSafePath(previous)
                    val previousLease = paths.requireSafePath(previous.resolve("lease.lock"))
                    if (!Files.isRegularFile(previousLease, NOFOLLOW_LINKS)) {
                        retained += row(relative(previous), "MISSING_OWNERSHIP_LEASE")
                        return@forEach
                    }
                    var recovered: Set<String>? = null
                    FileChannel.open(previousLease, WRITE, NOFOLLOW_LINKS).use { channel ->
                        val lock = try { channel.tryLock() } catch (_: OverlappingFileLockException) { null }
                        if (lock == null) {
                            retained += row(relative(previous), "ACTIVE_INVOCATION")
                        } else {
                            try {
                                val keep = readManifest(previous, previousId)
                                cleanup(previousId, keep)
                                recovered = keep
                            } finally {
                                lock.release()
                            }
                            // The channel must close before removing a lease on Windows.
                        }
                    }
                    recovered?.let { retireRecord(previous, previousId, it) }
                } catch (failure: Exception) {
                    failures += row(relative(previous), failure.javaClass.simpleName)
                }
            }
        }
    }

    private fun readManifest(directory: Path, id: String): Set<String> {
        val file = paths.requireInput(directory.resolve("manifest.json"))
        require(Files.size(file) <= 128 * 1024) { "cleanup manifest is too large" }
        val text = Files.readString(file)
        StrictJson.validateDocument(text)
        val values = JsonSlurper().parseText(text) as Map<*, *>
        require(values.keys == setOf("schemaVersion", "identity", "invocation", "entries", "protected"))
        require(values["schemaVersion"] == 1 && values["identity"] == identity && values["invocation"] == id) {
            "cleanup ownership does not match this module"
        }
        require(values["entries"] == entries(id)) { "cleanup manifest contains unexpected paths" }
        return (values["protected"] as List<*>).map { value ->
            val candidate = value as String
            require(entries(id).any { isWithin(candidate, it) || isWithin(it, candidate) })
            val normalized = root.resolve(candidate).toAbsolutePath().normalize()
            require(normalized.startsWith(root) && relative(normalized) == candidate)
            candidate
        }.toSet()
    }

    private fun writeManifest() {
        val file = paths.prepareOutput(manifest)
        val values = mapOf("schemaVersion" to 1, "identity" to identity, "invocation" to invocation,
            "entries" to entries(invocation), "protected" to protected.toList())
        AtomicFiles().replaceTransient(file, JsonOutput.toJson(values).toByteArray())
    }

    private fun cleanup(id: String, keep: Set<String>) {
        entries(id).forEach { entry ->
            try {
                val candidate = paths.requireSafePath(root.resolve(entry))
                if (!Files.exists(candidate, NOFOLLOW_LINKS)) return@forEach
                Files.walkFileTree(candidate, object : SimpleFileVisitor<Path>() {
                    override fun preVisitDirectory(directory: Path, attrs: BasicFileAttributes): FileVisitResult {
                        paths.requireSafePath(directory)
                        if (isProtected(directory, keep)) {
                            retained += row(relative(directory), "EXPLICIT_OUTPUT_OR_PREEXISTING")
                            return FileVisitResult.SKIP_SUBTREE
                        }
                        return FileVisitResult.CONTINUE
                    }

                    override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
                        if (isProtected(file, keep)) {
                            retained += row(relative(file), "EXPLICIT_OUTPUT_OR_PREEXISTING")
                        } else {
                            try {
                                paths.requireSafePath(file)
                                require(attrs.isRegularFile) { "non-regular scratch file" }
                                val current = Files.readAttributes(file, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
                                require(current.isRegularFile && current.fileKey() == attrs.fileKey()) { "scratch file identity changed" }
                                if (Files.deleteIfExists(file)) {
                                    deletedFiles++
                                    deletedBytes += attrs.size()
                                }
                            } catch (failure: Exception) {
                                failures += row(relative(file), failure.javaClass.simpleName)
                            }
                        }
                        return FileVisitResult.CONTINUE
                    }

                    override fun visitFileFailed(file: Path, failure: java.io.IOException): FileVisitResult {
                        failures += row(relative(file), failure.javaClass.simpleName)
                        return FileVisitResult.CONTINUE
                    }

                    override fun postVisitDirectory(directory: Path, failure: java.io.IOException?): FileVisitResult {
                        if (failure != null) {
                            failures += row(relative(directory), failure.javaClass.simpleName)
                        } else if (!isProtected(directory, keep)) {
                            try {
                                paths.requireSafePath(directory)
                                Files.newDirectoryStream(directory).use { children ->
                                    if (!children.iterator().hasNext() && Files.deleteIfExists(directory)) deletedDirectories++
                                }
                            } catch (problem: Exception) {
                                failures += row(relative(directory), problem.javaClass.simpleName)
                            }
                        }
                        return FileVisitResult.CONTINUE
                    }
                })
            } catch (failure: Exception) {
                failures += row(entry, failure.javaClass.simpleName)
            }
        }
        // Failed invocations may never write a report. Do not leave one empty
        // invocation directory per run after their scratch files have gone.
        val directory = root.resolve("hardening/$variant/invocations/$id")
        try {
            paths.requireSafePath(directory)
            if (Files.isDirectory(directory, NOFOLLOW_LINKS) && !isProtected(directory, keep)) {
                Files.newDirectoryStream(directory).use { children ->
                    if (!children.iterator().hasNext() && Files.deleteIfExists(directory)) deletedDirectories++
                }
            }
        } catch (failure: Exception) {
            failures += row(relative(directory), failure.javaClass.simpleName)
        }
    }

    private fun retireRecord(directory: Path, id: String, keep: Set<String>) {
        val remaining = entries(id).any { Files.exists(root.resolve(it), NOFOLLOW_LINKS) }
        if (remaining) return
        paths.requireSafePath(directory)
        for (name in listOf("manifest.json", "lease.lock")) {
            val file = paths.requireSafePath(directory.resolve(name))
            if (Files.exists(file, NOFOLLOW_LINKS)) {
                require(Files.isRegularFile(file, NOFOLLOW_LINKS))
                Files.delete(file)
            }
        }
        Files.newDirectoryStream(directory).use { children ->
            if (!children.iterator().hasNext()) Files.delete(directory)
        }
    }

    private fun discoverLegacy() {
        if (!Files.isDirectory(base, NOFOLLOW_LINKS)) return
        Files.newDirectoryStream(base, "prepared-*").use { directories ->
            directories.forEach { previous ->
                val id = previous.fileName.toString().removePrefix("prepared-")
                if (id.matches(ID) && id != invocation && !Files.exists(records.resolve(id), NOFOLLOW_LINKS)) {
                    retained += row(relative(previous), "LEGACY_WITHOUT_LIFETIME_LEASE")
                }
            }
        }
    }

    private fun writeReport() {
        val output = paths.prepareOutput(report)
        val values = mapOf("schemaVersion" to 1, "variant" to variant, "invocation" to invocation,
            "status" to if (failures.isEmpty()) "PASS" else "PARTIAL",
            "deletedFiles" to deletedFiles, "deletedDirectories" to deletedDirectories,
            "deletedBytes" to deletedBytes, "retained" to retained.distinct(), "failures" to failures.distinct())
        AtomicFiles().replaceTransient(output, JsonOutput.prettyPrint(JsonOutput.toJson(values)).toByteArray())
    }

    private fun isProtected(path: Path, keep: Set<String>): Boolean {
        val relative = relative(path)
        return keep.any { isWithin(relative, it) }
    }

    private fun relative(path: Path): String = root.relativize(path).toString().replace('\\', '/')
    private fun row(path: String, reason: String) = mapOf("path" to path, "reason" to reason)

    private fun releaseLease() {
        try { lease?.release() } finally {
            lease = null
            leaseChannel?.close()
            leaseChannel = null
        }
    }

    private fun <T> withRegistryLock(action: () -> T): T {
        val file = paths.prepareOutput(records.resolve("registry.lock"))
        return FileChannel.open(file, CREATE, WRITE, NOFOLLOW_LINKS).use { channel ->
            val deadline = System.nanoTime() + 10_000_000_000L
            var acquired: FileLock? = null
            while (acquired == null) {
                acquired = try { channel.tryLock() } catch (_: OverlappingFileLockException) { null }
                if (acquired == null) {
                    check(System.nanoTime() < deadline) { "cleanup registry is busy" }
                    Thread.sleep(20)
                }
            }
            try { action() } finally { acquired.release() }
        }
    }

    companion object {
        private val ID = Regex("[0-9a-f]{64}")
        private fun isWithin(path: String, parent: String) = path == parent || path.startsWith("$parent/")
        private fun entries(id: String, variant: String): List<String> {
            val base = "hardening/$variant"
            return listOf("$base/prepared-$id", "$base/invocations/$id/scratch",
                "$base/invocations/$id/unsigned.aab", "$base/invocations/$id/signed-candidate.aab",
                "$base/invocations/$id/verified.aab",
                "$base/invocations/$id/owned-artifact-inventory.json", "$base/invocations/$id/owned-artifact-analysis-inventory.json")
        }
    }

    private fun entries(id: String) = entries(id, variant)
}
