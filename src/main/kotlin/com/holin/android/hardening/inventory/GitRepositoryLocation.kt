package com.holin.android.hardening.inventory

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path

internal object GitRepositoryLocation {
    fun infoExclude(root: Path, gitExecutable: String = "git"): Path? {
        val process = gitProcessBuilder(
            gitExecutable,
            listOf("-C", root.toString(), "rev-parse", "--git-path", "info/exclude"),
        )
            .redirectErrorStream(true)
            .apply { environment()["LC_ALL"] = "C" }
            .start()
        val output = process.inputStream.use { it.readBytes().toString(Charsets.UTF_8).trim() }
        val exitCode = process.waitFor()
        if (exitCode == 128 && output.startsWith("fatal: not a git repository") &&
            System.getenv("GIT_DIR").isNullOrBlank() &&
            generateSequence(root) { it.parent }.none { Files.exists(it.resolve(".git"), NOFOLLOW_LINKS) }
        ) return null
        check(exitCode == 0 && output.isNotEmpty()) {
            "git rev-parse --git-path info/exclude failed with exit $exitCode: $output"
        }
        val path = Path.of(output)
        return (if (path.isAbsolute) path else root.resolve(path)).toAbsolutePath().normalize()
    }
}

internal fun gitProcessBuilder(gitExecutable: String, arguments: List<String>): ProcessBuilder =
    ProcessBuilder(listOf(gitExecutable) + arguments).apply {
        val developerDirectory = environment()["DEVELOPER_DIR"]
        val hasUsableDeveloperDirectory = developerDirectory?.takeIf(String::isNotBlank)?.let { value ->
            runCatching { Files.isDirectory(Path.of(value)) }.getOrDefault(false)
        } == true
        if (!hasUsableDeveloperDirectory) {
            environment().remove("DEVELOPER_DIR")
        }
    }
