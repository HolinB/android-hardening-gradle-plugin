package com.holin.android.hardening.device

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path

data class DeviceAcceptanceRequest(
    val sdkDirectory: Path,
    val serial: String?,
    val autoSelectSingleDevice: Boolean,
    val applicationId: String,
    val launchActivity: String,
    val stabilitySeconds: Int,
    val universalApk: Path,
)

data class AdbCommandResult(
    val exitCode: Int,
    val standardOutput: String,
    val standardError: String,
)

class DeviceAcceptanceRunner(
    private val executor: (List<String>) -> AdbCommandResult = ::executeProcess,
    private val sleeper: (Long) -> Unit = Thread::sleep,
) {
    fun smoke(request: DeviceAcceptanceRequest) {
        require(request.applicationId.isNotBlank()) { "device acceptance applicationId must be nonblank" }
        require(request.launchActivity.isNotBlank()) { "device acceptance launchActivity must be nonblank" }
        require(request.stabilitySeconds > 0) { "device acceptance stabilitySeconds must be greater than zero" }
        require(Files.isRegularFile(request.universalApk, NOFOLLOW_LINKS) && !Files.isSymbolicLink(request.universalApk)) {
            "device acceptance universal APK is missing or unsafe"
        }
        val adb = resolveAdb(request.sdkDirectory)
        val devices = run(listOf(adb.toString(), "devices"), "list connected devices")
        val serial = AdbDeviceSelector.select(request.serial, request.autoSelectSingleDevice, devices)
        val bound = listOf(adb.toString(), "-s", serial)
        run(bound + listOf("install", "-r", request.universalApk.toString()), "install hardened universal APK")
        run(bound + listOf("logcat", "-b", "crash", "-c"), "clear crash buffer")
        run(
            bound + listOf("shell", "am", "start", "-n", "${request.applicationId}/${request.launchActivity}"),
            "launch hardened application",
        )
        awaitForeground(bound, request.applicationId)
        repeat(request.stabilitySeconds) {
            sleeper(1_000L)
            checkForegroundAndPid(bound, request.applicationId)
        }
        val crashBuffer = run(bound + listOf("logcat", "-b", "crash", "-d"), "read crash buffer")
        val applicationIdPattern = Regex(
            "(?<![A-Za-z0-9_.])${Regex.escape(request.applicationId)}(?![A-Za-z0-9_.])",
        )
        check(crashBuffer.lineSequence().none(applicationIdPattern::containsMatchIn)) {
            "device acceptance crash buffer contains an entry for ${request.applicationId}"
        }
    }

    private fun awaitForeground(bound: List<String>, applicationId: String) {
        var lastResumedPackages = emptyList<String>()
        repeat(LAUNCH_READY_ATTEMPTS) { attempt ->
            val foreground = run(
                bound + listOf("shell", "dumpsys", "activity", "activities"),
                "check launched application readiness",
            )
            lastResumedPackages = resumedPackages(foreground).toList()
            if (lastResumedPackages.any(applicationId::equals)) {
                if (isPidReady(bound, applicationId)) return
            }
            if (attempt + 1 < LAUNCH_READY_ATTEMPTS) sleeper(1_000L)
        }
        if (lastResumedPackages.any(applicationId::equals)) {
            error(
                "device acceptance application PID is not ready after " +
                    "$LAUNCH_READY_ATTEMPTS readiness checks",
            )
        }
        error(
            "device acceptance foreground package is not $applicationId after " +
                "$LAUNCH_READY_ATTEMPTS readiness checks; resumed=$lastResumedPackages",
        )
    }

    private fun isPidReady(bound: List<String>, applicationId: String): Boolean {
        val result = executor(bound + listOf("shell", "pidof", applicationId))
        if (result.exitCode == 1 && result.standardError.isBlank()) return false
        check(result.exitCode == 0) {
            "adb failed to check application PID (exit ${result.exitCode}): ${result.standardError.trim()}"
        }
        val pid = result.standardOutput.trim()
        return pid.isNotBlank() && pid.split(Regex("\\s+")).all(PID::matches)
    }

    private fun checkForegroundAndPid(bound: List<String>, applicationId: String) {
        val foreground = run(
            bound + listOf("shell", "dumpsys", "activity", "activities"),
            "check foreground application",
        )
        check(resumedPackages(foreground).any(applicationId::equals)) {
            "device acceptance foreground package is not $applicationId"
        }
        checkPid(bound, applicationId)
    }

    private fun checkPid(bound: List<String>, applicationId: String) {
        val pid = run(bound + listOf("shell", "pidof", applicationId), "check application PID").trim()
        check(pid.split(Regex("\\s+")).all(PID::matches) && pid.isNotBlank()) {
            "device acceptance application PID is missing or invalid"
        }
    }

    private fun resolveAdb(sdkDirectory: Path): Path {
        val platformTools = sdkDirectory.toAbsolutePath().normalize().resolve("platform-tools")
        val candidates = listOf(platformTools.resolve("adb"), platformTools.resolve("adb.exe"))
        return candidates.firstOrNull { path ->
            Files.isRegularFile(path, NOFOLLOW_LINKS) && !Files.isSymbolicLink(path)
        } ?: throw IllegalArgumentException("Android SDK adb executable is missing")
    }

    private fun run(command: List<String>, operation: String): String {
        val result = executor(command)
        check(result.exitCode == 0) {
            "adb failed to $operation (exit ${result.exitCode}): ${result.standardError.trim()}"
        }
        return result.standardOutput
    }

    private fun resumedPackages(dumpsys: String): Sequence<String> = dumpsys.lineSequence()
        .filter { line ->
            line.contains("mResumedActivity") ||
                line.contains("topResumedActivity") ||
                line.trimStart().startsWith("ResumedActivity:")
        }
        .flatMap { line -> COMPONENT.findAll(line).map { match -> match.groupValues[1] } }

    private companion object {
        const val LAUNCH_READY_ATTEMPTS = 15
        val PID = Regex("[1-9][0-9]*")
        val COMPONENT = Regex("(?:^|\\s)([A-Za-z][A-Za-z0-9_.]*)/")

        fun executeProcess(command: List<String>): AdbCommandResult {
            val process = ProcessBuilder(command).start()
            val output = process.inputStream.bufferedReader().use { it.readText() }
            val error = process.errorStream.bufferedReader().use { it.readText() }
            return AdbCommandResult(process.waitFor(), output, error)
        }
    }
}

internal object AdbDeviceSelector {
    fun select(explicitSerial: String?, autoSelectSingleDevice: Boolean, adbDevicesOutput: String): String {
        explicitSerial?.let { serial ->
            require(serial.isNotBlank() && serial.none(Char::isWhitespace)) {
                "androidHardeningDeviceSerial must be a single nonblank token"
            }
        }
        val discovered = parse(adbDevicesOutput)
        explicitSerial?.let { serial ->
            check(discovered.count { it.serial == serial && it.state == "device" } == 1) {
                failure("configured device $serial is not online", discovered)
            }
            return serial
        }
        check(autoSelectSingleDevice) {
            failure("device auto-selection is disabled and no serial was provided", discovered)
        }
        check(discovered.size == 1 && discovered.single().state == "device") {
            failure("device auto-selection requires exactly one online device", discovered)
        }
        return discovered.single().serial
    }

    private fun parse(output: String): List<AdbDevice> = output.lineSequence().mapNotNull { line ->
        val trimmed = line.trim()
        if (trimmed.isBlank() || trimmed.startsWith("List of devices attached") || trimmed.startsWith('*')) {
            return@mapNotNull null
        }
        val fields = trimmed.split(Regex("\\s+"))
        fields.takeIf { it.size >= 2 }?.let { AdbDevice(it[0], it[1]) }
    }.toList()

    private fun failure(reason: String, discovered: List<AdbDevice>): String =
        "$reason; discovered=${discovered.joinToString(prefix = "[", postfix = "]") { "${it.serial}(${it.state})" }}; " +
            "provide -PandroidHardeningDeviceSerial=<serial>"

    private data class AdbDevice(val serial: String, val state: String)
}
