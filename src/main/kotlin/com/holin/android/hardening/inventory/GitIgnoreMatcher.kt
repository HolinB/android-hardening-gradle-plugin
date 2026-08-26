package com.holin.android.hardening.inventory

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.Path
import kotlin.concurrent.thread

class GitIgnoreMatcher(
    repositoryRoot: Path,
    private val gitExecutable: String = "git",
) {
    private val root = repositoryRoot.toAbsolutePath().normalize()

    fun ignored(candidates: Collection<Path>): Set<Path> {
        if (candidates.isEmpty()) return emptySet()
        val byGitPath = linkedMapOf<String, Path>()
        candidates.forEach { candidate ->
            val absolute = candidate.toAbsolutePath().normalize()
            require(absolute.startsWith(root) && absolute != root) {
                "Git-ignore candidate must stay below repository root $root: $candidate"
            }
            val gitPath = root.relativize(absolute).toString().replace('\\', '/')
            byGitPath[gitPath] = absolute
        }

        val process = ProcessBuilder(
            gitExecutable,
            "-C",
            root.toString(),
            "check-ignore",
            "--no-index",
            "--stdin",
            "-z",
        ).start()
        val errorBytes = ByteArrayOutputStream()
        val errorReader = thread(name = "git-check-ignore-stderr", isDaemon = true) {
            process.errorStream.use { input -> input.copyTo(errorBytes) }
        }
        process.outputStream.use { input ->
            byGitPath.keys.forEach { relative ->
                input.write(relative.toByteArray(UTF_8))
                input.write(0)
            }
        }
        val output = process.inputStream.use { it.readBytes() }
        val exitCode = process.waitFor()
        errorReader.join()
        check(exitCode == 0 || exitCode == 1) {
            "git check-ignore failed with exit $exitCode: ${errorBytes.toString(UTF_8).trim()}"
        }
        return splitNullTerminated(output)
            .mapNotNullTo(linkedSetOf()) { ignoredPath -> byGitPath[ignoredPath] }
    }

    private fun splitNullTerminated(bytes: ByteArray): List<String> {
        val result = mutableListOf<String>()
        var start = 0
        bytes.forEachIndexed { index, byte ->
            if (byte.toInt() == 0) {
                if (index > start) result += String(bytes, start, index - start, UTF_8)
                start = index + 1
            }
        }
        check(start == bytes.size) { "git check-ignore returned a non-NUL-terminated path" }
        return result
    }
}
