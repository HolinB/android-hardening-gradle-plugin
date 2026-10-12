package com.holin.android.hardening.inventory

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
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

        if (GitRepositoryLocation.infoExclude(root, gitExecutable) != null) {
            return checkIgnored(byGitPath, emptyList())
        }
        // Reuse Git's complete ignore semantics for source archives, without creating a consumer repository.
        val metadata = Files.createTempDirectory("hardening-source-git-")
        return try {
            val init = ProcessBuilder(gitExecutable, "init", "--bare", "--template=", metadata.toString())
                .redirectErrorStream(true).start()
            val output = init.inputStream.use { it.readBytes().toString(UTF_8).trim() }
            check(init.waitFor() == 0) { "temporary Git metadata initialization failed: $output" }
            checkIgnored(byGitPath, listOf("--git-dir=$metadata", "--work-tree=$root", "-c", "core.bare=false"))
        } finally {
            Files.walk(metadata).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private fun checkIgnored(byGitPath: Map<String, Path>, context: List<String>): Set<Path> {
        val process = ProcessBuilder(listOf(gitExecutable, "-C", root.toString()) + context +
            listOf("check-ignore", "--no-index", "--stdin", "-z")).start()
        val errorBytes = ByteArrayOutputStream()
        val outputBytes = ByteArrayOutputStream()
        val errorReader = thread(true, true, null, "git-check-ignore-stderr") {
            process.errorStream.use { input -> input.copyTo(errorBytes) }
        }
        val outputReader = thread(true, true, null, "git-check-ignore-stdout") {
            process.inputStream.use { input -> input.copyTo(outputBytes) }
        }
        val writeResult = runCatching {
            process.outputStream.use { input ->
                byGitPath.keys.forEach { relative ->
                    input.write(relative.toByteArray(UTF_8))
                    input.write(0)
                }
            }
        }
        val exitCode = process.waitFor()
        errorReader.join()
        outputReader.join()
        check(exitCode == 0 || exitCode == 1) {
            "git check-ignore failed with exit $exitCode: ${errorBytes.toString(UTF_8).trim()}"
        }
        writeResult.getOrThrow()
        return splitNullTerminated(outputBytes.toByteArray())
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
