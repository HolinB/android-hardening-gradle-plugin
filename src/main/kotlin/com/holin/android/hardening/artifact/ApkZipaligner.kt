package com.holin.android.hardening.artifact

import java.nio.file.Files
import java.nio.file.Path

fun interface ApkZipalignCommandRunner {
    fun run(command: List<String>): Int
}

interface ApkZipalignOperation {
    fun align(zipalignExecutable: Path, inputApk: Path, outputApk: Path)
    fun verify(zipalignExecutable: Path, signedApk: Path)
}

class ApkZipaligner(
    private val commandRunner: ApkZipalignCommandRunner = ProcessApkZipalignCommandRunner,
) : ApkZipalignOperation {
    override fun align(zipalignExecutable: Path, inputApk: Path, outputApk: Path) {
        val executable = requireExecutable(zipalignExecutable)
        val input = inputApk.toAbsolutePath().normalize()
        val output = outputApk.toAbsolutePath().normalize()
        require(Files.isRegularFile(input)) { "unsigned APK alignment input is missing" }
        require(input != output) { "zipalign input and output must be distinct" }
        require(!Files.exists(output)) { "aligned APK output already exists" }
        val exitCode = try {
            commandRunner.run(
                listOf(executable.toString(), "-f", "-P", PAGE_ALIGNMENT_KIB, GENERAL_ALIGNMENT, input.toString(), output.toString()),
            )
        } catch (failure: Exception) {
            runCatching { Files.deleteIfExists(output) }
            throw IllegalStateException("zipalign execution failed (${failure.javaClass.simpleName})")
        }
        if (exitCode != 0) {
            runCatching { Files.deleteIfExists(output) }
            throw IllegalStateException("zipalign failed with exit $exitCode")
        }
        require(Files.isRegularFile(output)) { "zipalign did not produce an aligned APK" }
    }

    override fun verify(zipalignExecutable: Path, signedApk: Path) {
        val executable = requireExecutable(zipalignExecutable)
        val apk = signedApk.toAbsolutePath().normalize()
        require(Files.isRegularFile(apk)) { "signed APK zipalign verification input is missing" }
        val exitCode = try {
            commandRunner.run(
                listOf(executable.toString(), "-c", "-P", PAGE_ALIGNMENT_KIB, GENERAL_ALIGNMENT, apk.toString()),
            )
        } catch (failure: Exception) {
            throw IllegalStateException("zipalign verification execution failed (${failure.javaClass.simpleName})")
        }
        require(exitCode == 0) { "zipalign verification failed with exit $exitCode" }
    }

    private fun requireExecutable(path: Path): Path = path.toAbsolutePath().normalize().also { executable ->
        require(Files.isRegularFile(executable)) { "SDK zipalign executable is missing" }
    }

    private companion object {
        const val PAGE_ALIGNMENT_KIB = "16"
        const val GENERAL_ALIGNMENT = "4"
    }
}

private object ProcessApkZipalignCommandRunner : ApkZipalignCommandRunner {
    override fun run(command: List<String>): Int {
        val process = ProcessBuilder(command).redirectErrorStream(true).start()
        process.inputStream.use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (input.read(buffer) >= 0) Unit
        }
        return process.waitFor()
    }
}
