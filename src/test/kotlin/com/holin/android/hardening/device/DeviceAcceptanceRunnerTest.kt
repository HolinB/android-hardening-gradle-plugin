package com.holin.android.hardening.device

import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.createFile
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class DeviceAcceptanceRunnerTest {
    @TempDir
    lateinit var root: Path

    @Test
    fun `smoke accepts modern ResumedActivity output and verifies two stable seconds`() {
        val fixture = fixture()
        val commands = mutableListOf<List<String>>()
        val outputs = ArrayDeque(
            listOf(
                "List of devices attached\nSERIAL-1\tdevice\n",
                "Success\n",
                "",
                "Starting: Intent\n",
                "ResumedActivity: ActivityRecord{abc u0 com.example.demo.match/.ui.home.activity.SplashActivity t42}\n",
                "1234\n",
                "ResumedActivity: ActivityRecord{abc u0 com.example.demo.match/.ui.home.activity.SplashActivity t42}\n",
                "1234\n",
                "ResumedActivity: ActivityRecord{abc u0 com.example.demo.match/.ui.home.activity.SplashActivity t42}\n",
                "1234\n",
                "--------- beginning of crash\n",
            ),
        )
        val runner = DeviceAcceptanceRunner(
            executor = { command ->
                commands += command
                AdbCommandResult(0, outputs.removeFirst(), "")
            },
            sleeper = {},
        )

        runner.smoke(fixture.request(stabilitySeconds = 2))

        assertEquals("devices", commands.first().last())
        assertTrue(commands.drop(1).all { it.take(3) == listOf(fixture.adb.toString(), "-s", "SERIAL-1") })
        assertEquals(listOf("install", "-r", fixture.apk.toString()), commands[1].drop(3))
        assertEquals(listOf("logcat", "-b", "crash", "-c"), commands[2].drop(3))
        assertEquals(
            listOf("shell", "am", "start", "-n", "com.example.demo.match/.ui.home.activity.SplashActivity"),
            commands[3].drop(3),
        )
        assertEquals(listOf("logcat", "-b", "crash", "-d"), commands.last().drop(3))
    }

    @Test
    fun `smoke waits for the target activity before starting the stability window`() {
        val fixture = fixture()
        var foregroundChecks = 0
        var sleeps = 0
        val runner = DeviceAcceptanceRunner(
            { command ->
                val adbArguments = command.drop(3)
                val output = when {
                    command.last() == "devices" -> "List of devices attached\nSERIAL-1\tdevice\n"
                    adbArguments.take(2) == listOf("install", "-r") -> "Success\n"
                    adbArguments == listOf("logcat", "-b", "crash", "-c") -> ""
                    adbArguments.take(3) == listOf("shell", "am", "start") -> "Starting: Intent\n"
                    adbArguments == listOf("shell", "dumpsys", "activity", "activities") -> {
                        foregroundChecks += 1
                        if (foregroundChecks < 3) {
                            "mResumedActivity: com.sec.android.app.launcher/.Launcher\n"
                        } else {
                            "mResumedActivity: com.example.demo.match/.ui.home.activity.SplashActivity\n"
                        }
                    }
                    adbArguments == listOf("shell", "pidof", "com.example.demo.match") -> "1234\n"
                    adbArguments == listOf("logcat", "-b", "crash", "-d") -> ""
                    else -> error("unexpected command: $command")
                }
                AdbCommandResult(0, output, "")
            },
            { sleeps += 1 },
        )

        runner.smoke(fixture.request(stabilitySeconds = 1))

        assertEquals(4, foregroundChecks)
        assertEquals(3, sleeps)
    }

    @Test
    fun `smoke retries a transiently missing launch PID after activity is resumed`() {
        val fixture = fixture()
        var pidChecks = 0
        var sleeps = 0
        val runner = DeviceAcceptanceRunner(
            { command ->
                val adbArguments = command.drop(3)
                when {
                    command.last() == "devices" -> AdbCommandResult(
                        0,
                        "List of devices attached\nSERIAL-1\tdevice\n",
                        "",
                    )
                    adbArguments.take(2) == listOf("install", "-r") ->
                        AdbCommandResult(0, "Success\n", "")
                    adbArguments == listOf("logcat", "-b", "crash", "-c") ->
                        AdbCommandResult(0, "", "")
                    adbArguments.take(3) == listOf("shell", "am", "start") ->
                        AdbCommandResult(0, "Starting: Intent\n", "")
                    adbArguments == listOf("shell", "dumpsys", "activity", "activities") ->
                        AdbCommandResult(
                            0,
                            "mResumedActivity: com.example.demo.match/.ui.home.activity.SplashActivity\n",
                            "",
                        )
                    adbArguments == listOf("shell", "pidof", "com.example.demo.match") -> {
                        pidChecks += 1
                        if (pidChecks == 1) {
                            AdbCommandResult(1, "", "")
                        } else {
                            AdbCommandResult(0, "1234\n", "")
                        }
                    }
                    adbArguments == listOf("logcat", "-b", "crash", "-d") ->
                        AdbCommandResult(0, "", "")
                    else -> error("unexpected command: $command")
                }
            },
            { sleeps += 1 },
        )

        runner.smoke(fixture.request(stabilitySeconds = 1))

        assertEquals(3, pidChecks)
        assertEquals(2, sleeps)
    }

    @Test
    fun `smoke accepts an arbitrary resolved application id and launch activity`() {
        val fixture = fixture()
        val outputs = ArrayDeque(
            listOf(
                "List of devices attached\nSERIAL-1\tdevice\n",
                "Success\n",
                "",
                "Starting: Intent\n",
                "mResumedActivity: com.example.demo/com.example.demo.DemoActivity\n",
                "1234\n",
                "mResumedActivity: com.example.demo/com.example.demo.DemoActivity\n",
                "1234\n",
                "",
            ),
        )
        val runner = DeviceAcceptanceRunner(
            executor = { AdbCommandResult(0, outputs.removeFirst(), "") },
            sleeper = {},
        )

        runner.smoke(
            fixture.request(
                "com.example.demo",
                "com.example.demo.DemoActivity",
            ),
        )
    }

    @Test
    fun `smoke rejects a configured serial that is not online`() {
        val fixture = fixture()
        val runner = DeviceAcceptanceRunner({
            AdbCommandResult(0, "List of devices attached\nSERIAL-1\tunauthorized\n", "")
        })

        val failure = assertFailsWith<IllegalStateException> { runner.smoke(fixture.request()) }

        assertTrue(failure.message.orEmpty().contains("not online"))
    }

    @Test
    fun `smoke rejects package specific crash buffer entries`() {
        val fixture = fixture()
        val outputs = ArrayDeque(
            listOf(
                "List of devices attached\nSERIAL-1\tdevice\n",
                "Success\n",
                "",
                "Starting: Intent\n",
                "mResumedActivity: com.example.demo.match/.ui.home.activity.SplashActivity\n",
                "1234\n",
                "mResumedActivity: com.example.demo.match/.ui.home.activity.SplashActivity\n",
                "1234\n",
                "FATAL EXCEPTION: main Process: com.example.demo.match\n",
            ),
        )
        val runner = DeviceAcceptanceRunner(
            { AdbCommandResult(0, outputs.removeFirst(), "") },
            {},
        )

        val failure = assertFailsWith<IllegalStateException> {
            runner.smoke(fixture.request(stabilitySeconds = 1))
        }

        assertTrue(failure.message.orEmpty().contains("crash buffer"))
    }

    @Test
    fun `smoke rejects a resumed package that only prefixes the Demo package`() {
        val fixture = fixture()
        val runner = DeviceAcceptanceRunner(
            executor = { command ->
                val adbArguments = command.drop(3)
                val output = when {
                    command.last() == "devices" -> "List of devices attached\nSERIAL-1\tdevice\n"
                    adbArguments.take(2) == listOf("install", "-r") -> "Success\n"
                    adbArguments == listOf("logcat", "-b", "crash", "-c") -> ""
                    adbArguments.take(3) == listOf("shell", "am", "start") -> "Starting: Intent\n"
                    adbArguments == listOf("shell", "dumpsys", "activity", "activities") ->
                        "mResumedActivity: com.example.demo.match.debug/.ui.home.activity.SplashActivity\n"
                    adbArguments == listOf("shell", "pidof", "com.example.demo.match") -> "1234\n"
                    adbArguments == listOf("logcat", "-b", "crash", "-d") -> ""
                    else -> error("unexpected command: $command")
                }
                AdbCommandResult(0, output, "")
            },
            sleeper = {},
        )

        val failure = assertFailsWith<IllegalStateException> {
            runner.smoke(fixture.request(stabilitySeconds = 1))
        }

        assertTrue(failure.message.orEmpty().contains("foreground package"))
    }

    private fun fixture(): Fixture {
        val sdk = root.resolve("sdk")
        val adb = sdk.resolve("platform-tools/adb").also { it.parent.createDirectories(); it.createFile() }
        val apk = root.resolve("candidate.apk").createFile()
        return Fixture(sdk, adb, apk)
    }

    private data class Fixture(val sdk: Path, val adb: Path, val apk: Path) {
        fun request(
            applicationId: String = "com.example.demo.match",
            launchActivity: String = ".ui.home.activity.SplashActivity",
            stabilitySeconds: Int = 1,
        ) = DeviceAcceptanceRequest(
            sdk,
            "SERIAL-1",
            true,
            applicationId,
            launchActivity,
            stabilitySeconds,
            apk,
        )
    }
}
