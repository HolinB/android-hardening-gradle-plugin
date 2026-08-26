package com.holin.buildsupport

import java.net.URI
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.StandardOpenOption.CREATE
import java.nio.file.StandardOpenOption.WRITE
import java.security.MessageDigest
import java.util.Comparator
import java.util.zip.ZipInputStream

data class GradleDistributionSpec(val version: String, val sha256: String) {
    init {
        require(VERSION.matches(version)) { "Gradle distribution version is malformed: $version" }
        require(SHA256.matches(sha256)) { "Gradle distribution SHA-256 is malformed for $version" }
    }

    val uri: URI = URI.create("https://services.gradle.org/distributions/gradle-$version-bin.zip")

    private companion object {
        val VERSION = Regex("[0-9]+\\.[0-9]+(?:\\.[0-9]+)?")
        val SHA256 = Regex("[0-9a-f]{64}")
    }
}

fun interface DistributionDownloader {
    fun download(uri: URI, target: Path)
}

class GradleDistributionProvisioner(
    private val downloader: DistributionDownloader = DistributionDownloader(::download),
) {
    fun ensure(gradleUserHome: Path, spec: GradleDistributionSpec, offline: Boolean): Path {
        existingWrapperDistribution(gradleUserHome, spec.version)?.let { return it }
        val managed = managedDistribution(gradleUserHome, spec.version)
        if (isComplete(managed)) return managed
        if (offline && Files.exists(managed)) {
            error("managed Gradle ${spec.version} distribution is incomplete: $managed")
        }
        check(!offline) {
            "Gradle ${spec.version} distribution is unavailable in offline mode; " +
                "run prepareOfflineTestKitEnvironment once while online"
        }

        val locks = gradleUserHome.resolve("holin-hardening/locks")
        Files.createDirectories(locks)
        val lock = locks.resolve("gradle-${spec.version}.lock")
        FileChannel.open(lock, CREATE, WRITE).use { channel ->
            channel.lock().use {
                existingWrapperDistribution(gradleUserHome, spec.version)?.let { return it }
                if (isComplete(managed)) return managed
                deleteTree(managed)
                return install(gradleUserHome, spec, managed)
            }
        }
    }

    private fun install(gradleUserHome: Path, spec: GradleDistributionSpec, destination: Path): Path {
        val downloads = gradleUserHome.resolve("holin-hardening/downloads")
        Files.createDirectories(downloads)
        val temporary = Files.createTempDirectory(downloads, "gradle-${spec.version}-")
        try {
            val archive = temporary.resolve("gradle-${spec.version}-bin.zip")
            downloader.download(spec.uri, archive)
            val actual = sha256(archive)
            require(actual == spec.sha256) {
                "Gradle ${spec.version} distribution checksum mismatch: expected=${spec.sha256}, actual=$actual"
            }
            val extraction = temporary.resolve("extracted")
            Files.createDirectories(extraction)
            unzip(archive, extraction)
            val extractedHome = extraction.resolve("gradle-${spec.version}")
            require(isComplete(extractedHome)) {
                "Gradle ${spec.version} distribution archive is incomplete"
            }
            extractedHome.resolve("bin/gradle").toFile().setExecutable(true, false)
            Files.createDirectories(destination.parent)
            move(extractedHome, destination)
            return destination
        } finally {
            deleteTree(temporary)
        }
    }

    private fun existingWrapperDistribution(gradleUserHome: Path, version: String): Path? {
        val distributions = gradleUserHome.resolve("wrapper/dists/gradle-$version-bin")
        if (!Files.isDirectory(distributions)) return null
        return Files.walk(distributions, 3).use { paths ->
            paths.filter { path -> path.fileName.toString() == "gradle-$version" && isComplete(path) }
                .sorted()
                .findFirst()
                .orElse(null)
        }
    }

    private fun managedDistribution(gradleUserHome: Path, version: String): Path =
        gradleUserHome.resolve("holin-hardening/distributions/$version/gradle-$version")

    private fun isComplete(path: Path): Boolean =
        Files.isDirectory(path) && Files.isRegularFile(path.resolve("bin/gradle"))

    private fun unzip(archive: Path, destination: Path) {
        val normalizedDestination = destination.toAbsolutePath().normalize()
        val names = mutableSetOf<String>()
        ZipInputStream(Files.newInputStream(archive)).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                require(names.add(entry.name)) { "Gradle distribution contains duplicate entry ${entry.name}" }
                val output = normalizedDestination.resolve(entry.name).normalize()
                require(output.startsWith(normalizedDestination) && output != normalizedDestination) {
                    "Gradle distribution contains unsafe entry ${entry.name}"
                }
                if (entry.isDirectory) {
                    Files.createDirectories(output)
                } else {
                    Files.createDirectories(output.parent)
                    Files.copy(zip, output, REPLACE_EXISTING)
                }
                zip.closeEntry()
            }
        }
    }

    private fun move(source: Path, destination: Path) {
        runCatching { Files.move(source, destination, ATOMIC_MOVE) }
            .getOrElse { Files.move(source, destination) }
    }

    private fun deleteTree(root: Path) {
        if (Files.notExists(root)) return
        Files.walk(root).use { paths ->
            paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    private fun sha256(path: Path): String = Files.newInputStream(path).use { input ->
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            digest.update(buffer, 0, count)
        }
        digest.digest().joinToString("") { byte -> "%02x".format(byte) }
    }

    private companion object {
        fun download(uri: URI, target: Path) {
            val connection = uri.toURL().openConnection().apply {
                connectTimeout = 30_000
                readTimeout = 120_000
            }
            connection.getInputStream().use { input -> Files.copy(input, target, REPLACE_EXISTING) }
        }
    }
}
