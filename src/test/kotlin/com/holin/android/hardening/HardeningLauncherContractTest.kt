package com.holin.android.hardening

import com.sun.net.httpserver.HttpServer
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.net.InetSocketAddress
import java.net.URI
import java.net.URLClassLoader
import java.lang.reflect.InvocationTargetException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import java.util.zip.CRC32
import javax.tools.ToolProvider
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.io.path.createDirectories
import kotlin.io.path.readLines
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.io.TempDir

class HardeningLauncherContractTest {
    @TempDir
    lateinit var temporary: Path

    @Test
    fun `launcher reports the plugin version without Gradle`() {
        val result = runLauncher(listOf("--version"), emptyMap())

        assertEquals(0, result.exitCode)
        assertEquals("1.3.0", result.output.trim())
    }

    @Test
    fun `valid cached repository is forwarded to the consumer wrapper`() {
        val project = consumerProject()
        val sdk = androidSdk()
        val cache = temporary.resolve("cache")
        cachedRepository(cache)
        val arguments = temporary.resolve("arguments.txt")

        val result = runLauncher(
            listOf(
                "--project-dir",
                project.toString(),
                "--",
                "-PandroidHardening=true",
                ":app:hardeningBundleDemoRelease",
            ),
            mapOf(
                "ANDROID_SDK_ROOT" to sdk.toString(),
                "HARDENING_CACHE_HOME" to cache.toString(),
                "HARDENING_ARGUMENT_LOG" to arguments.toString(),
            ),
        )

        assertEquals(0, result.exitCode, result.output)
        val forwarded = arguments.readLines()
        assertTrue(forwarded.first().startsWith("-PhardeningPluginRepo="))
        assertEquals(
            listOf(
                forwarded.first(),
                "-PandroidHardening=true",
                ":app:hardeningBundleDemoRelease",
            ),
            forwarded,
        )
    }

    @Test
    fun `offline invocation lists a missing portable repository without running Gradle`() {
        val project = consumerProject()
        val result = runLauncher(
            listOf("--project-dir", project.toString(), "--", "--offline", "tasks"),
            mapOf(
                "ANDROID_SDK_ROOT" to androidSdk().toString(),
                "HARDENING_CACHE_HOME" to temporary.resolve("empty-cache").toString(),
                "HARDENING_PLUGIN_SOURCE_DIR" to temporary.resolve("missing-source").toString(),
            ),
        )

        assertEquals(2, result.exitCode)
        assertContains(result.output, "portable repository")
        assertContains(result.output, "offline")
    }

    @Test
    fun `consumer wrapper accepts Gradle all distributions`() {
        val cache = temporary.resolve("all-distribution-cache")
        val arguments = temporary.resolve("all-distribution-args.txt")
        cachedRepository(cache)

        val result = runLauncher(
            listOf(
                "--project-dir",
                consumerProject("distributionUrl=https\\://services.gradle.org/distributions/gradle-8.13-all.zip\n").toString(),
                "--",
                "tasks",
            ),
            mapOf(
                "ANDROID_SDK_ROOT" to androidSdk().toString(),
                "HARDENING_CACHE_HOME" to cache.toString(),
                "HARDENING_ARGUMENT_LOG" to arguments.toString(),
            ),
        )

        assertEquals(0, result.exitCode, result.output)
    }

    @Test
    fun `consumer wrapper rejects Gradle versions below 8 10`() {
        val cache = temporary.resolve("below-minimum-cache")
        cachedRepository(cache)

        val result = runLauncher(
            listOf(
                "--project-dir",
                consumerProject("distributionUrl=https\\://services.gradle.org/distributions/gradle-8.9-bin.zip\n").toString(),
                "--",
                "tasks",
            ),
            mapOf(
                "ANDROID_SDK_ROOT" to androidSdk().toString(),
                "HARDENING_CACHE_HOME" to cache.toString(),
                "HARDENING_ARGUMENT_LOG" to temporary.resolve("below-minimum-args.txt").toString(),
            ),
        )

        assertEquals(2, result.exitCode)
        assertContains(result.output, "actual=8.9")
    }

    @Test
    fun `consumer wrapper ignores misleading Gradle comments`() {
        val cache = temporary.resolve("misleading-comment-cache")
        cachedRepository(cache)
        val properties =
            "# distributionUrl=https\\://services.gradle.org/distributions/gradle-8.13-bin.zip\n" +
                "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.9-bin.zip\n"

        val result = runLauncher(
            listOf("--project-dir", consumerProject(properties).toString(), "--", "tasks"),
            mapOf(
                "ANDROID_SDK_ROOT" to androidSdk().toString(),
                "HARDENING_CACHE_HOME" to cache.toString(),
                "HARDENING_ARGUMENT_LOG" to temporary.resolve("misleading-comment-args.txt").toString(),
            ),
        )

        assertEquals(2, result.exitCode)
        assertContains(result.output, "actual=8.9")
    }

    @Test
    fun `entry points preflight JDK 17 before launching the source file`() {
        val root = Path.of("").toAbsolutePath().normalize()
        listOf("hardeningw", "hardeningw.ps1", "hardeningw.bat").forEach { launcher ->
            val content = Files.readString(root.resolve(launcher))

            assertContains(content, "JDK 17 or newer is required")
            assertTrue(content.indexOf("JDK 17 or newer is required") < content.indexOf("HardeningLauncher.java"))
        }
    }

    @Test
    fun `POSIX entry point rejects Java 8 and 11 before source launch`() {
        assumeTrue(!System.getProperty("os.name").startsWith("Windows", true))
        val root = Path.of("").toAbsolutePath().normalize()

        listOf(
            "java version \"1.8.0_422\"",
            "openjdk version \"11.0.27\"",
        ).forEach { versionOutput ->
            val fakeJava = fakeJava(versionOutput)
            val process = ProcessBuilder(root.resolve("hardeningw").toString(), "--version")
                .directory(root.toFile())
                .redirectErrorStream(true)
                .also { builder ->
                    builder.environment()["PATH"] = fakeJava.bin.toString() + System.getProperty("path.separator") + builder.environment().getValue("PATH")
                    builder.environment()["HARDENING_SOURCE_LAUNCH_MARKER"] = fakeJava.sourceLaunchMarker.toString()
                }
                .start()
            val output = process.inputStream.bufferedReader().use { it.readText() }

            assertEquals(2, process.waitFor(), output)
            assertContains(output, "JDK 17 or newer is required")
            assertTrue(Files.notExists(fakeJava.sourceLaunchMarker), output)
        }
    }

    @Test
    fun `PowerShell preflight writes directly to stderr`() {
        val root = Path.of("").toAbsolutePath().normalize()
        val content = Files.readString(root.resolve("hardeningw.ps1"))

        assertContains(content, "[Console]::Error.WriteLine")
        assertFalse(content.contains("Write-Error"))
    }

    @Test
    fun `PowerShell entry point rejects Java 11 before source launch when pwsh is available`() {
        assumeTrue(powerShellAvailable(), "pwsh is unavailable")
        val root = Path.of("").toAbsolutePath().normalize()
        val fakeJava = fakeJava("openjdk version \"11.0.27\"")
        val process = ProcessBuilder("pwsh", "-NoProfile", "-File", root.resolve("hardeningw.ps1").toString(), "--version")
            .directory(root.toFile())
            .redirectErrorStream(true)
            .also { builder ->
                builder.environment()["PATH"] = fakeJava.bin.toString() + System.getProperty("path.separator") + builder.environment().getValue("PATH")
                builder.environment()["HARDENING_SOURCE_LAUNCH_MARKER"] = fakeJava.sourceLaunchMarker.toString()
            }
            .start()
        val output = process.inputStream.bufferedReader().use { it.readText() }

        assertEquals(2, process.waitFor(), output)
        assertContains(output, "JDK 17 or newer is required")
        assertTrue(Files.notExists(fakeJava.sourceLaunchMarker), output)
    }

    @Test
    fun `http failure falls back to a local source archive`() {
        val sourceArchive = portableArchive("source-plugin")
        val source = sourceProject(sourceArchive)
        val server = server { exchange ->
            exchange.sendResponseHeaders(503, -1)
            exchange.close()
        }
        try {
            val result = runLauncher(
                listOf("--project-dir", consumerProject().toString(), "--", "tasks"),
                mapOf(
                    "ANDROID_SDK_ROOT" to androidSdk().toString(),
                    "HARDENING_CACHE_HOME" to temporary.resolve("http-fallback-cache").toString(),
                    "HARDENING_PLUGIN_SOURCE_DIR" to source.toString(),
                    "HARDENING_RELEASE_URL" to releaseUrl(server),
                    "HARDENING_ARGUMENT_LOG" to temporary.resolve("http-fallback-args.txt").toString(),
                ),
            )

            assertEquals(0, result.exitCode, result.output)
            assertTrue(source.resolve("source-build-ran").toFile().exists())
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun `checksum verified download returns the release archive`() {
        val archive = portableArchive("release-plugin")
        val server = server { exchange ->
            exchange.sendResponseHeaders(200, Files.size(archive))
            Files.newInputStream(archive).use { input -> exchange.responseBody.use { input.copyTo(it) } }
        }
        try {
            val downloaded = downloadRelease(temporary.resolve("download-cache"), releaseUrl(server), sha256(archive))

            assertEquals(sha256(archive), sha256(downloaded))
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun `non successful HTTP responses remove temporary archives even when the body checksum matches`() {
        val archive = portableArchive("release-plugin")
        val cache = temporary.resolve("non-success-download-cache")
        val server = server { exchange ->
            exchange.sendResponseHeaders(503, Files.size(archive))
            Files.newInputStream(archive).use { input -> exchange.responseBody.use { input.copyTo(it) } }
        }
        try {
            val downloaded = downloadReleaseOrNull(cache, releaseUrl(server), sha256(archive))

            assertEquals(null, downloaded)
            Files.list(cache.resolve("downloads")).use { paths ->
                assertEquals(0L, paths.count())
            }
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun `concurrent launchers build one shared cache repository`() {
        val source = sourceProject(portableArchive("source-plugin"))
        val cache = temporary.resolve("concurrent-cache")
        val sdk = androidSdk()
        val server = server { exchange ->
            exchange.sendResponseHeaders(503, -1)
            exchange.close()
        }
        val start = CountDownLatch(1)
        val first = AtomicReference<ProcessResult?>()
        val second = AtomicReference<ProcessResult?>()
        fun launch(project: Path, result: AtomicReference<ProcessResult?>): Thread = Thread {
            start.await()
            result.set(
                runLauncher(
                    listOf("--project-dir", project.toString(), "--", "tasks"),
                    mapOf(
                        "ANDROID_SDK_ROOT" to sdk.toString(),
                        "HARDENING_CACHE_HOME" to cache.toString(),
                        "HARDENING_PLUGIN_SOURCE_DIR" to source.toString(),
                        "HARDENING_RELEASE_URL" to releaseUrl(server),
                        "HARDENING_ARGUMENT_LOG" to temporary.resolve("${project.fileName}.args").toString(),
                    ),
                ),
            )
        }
        val firstThread = launch(consumerProject(), first)
        val secondThread = launch(consumerProject(), second)
        try {
            firstThread.start()
            secondThread.start()
            start.countDown()
            firstThread.join(TimeUnit.SECONDS.toMillis(20))
            secondThread.join(TimeUnit.SECONDS.toMillis(20))

            assertTrue(!firstThread.isAlive && !secondThread.isAlive, "concurrent launchers did not complete")
            assertEquals(0, first.get()?.exitCode)
            assertEquals(0, second.get()?.exitCode)
            assertEquals(1, source.resolve("source-build.log").readLines().size)
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun `release checksum mismatch is a hard failure without source fallback`() {
        val sourceArchive = portableArchive("source-plugin")
        val source = sourceProject(sourceArchive)
        val server = server { exchange ->
            val archive = portableArchive("release-plugin")
            exchange.sendResponseHeaders(200, Files.size(archive))
            Files.newInputStream(archive).use { input -> exchange.responseBody.use { input.copyTo(it) } }
        }
        try {
            val result = runLauncher(
                listOf("--project-dir", consumerProject().toString(), "--", "tasks"),
                mapOf(
                    "ANDROID_SDK_ROOT" to androidSdk().toString(),
                    "HARDENING_CACHE_HOME" to temporary.resolve("checksum-failure-cache").toString(),
                    "HARDENING_PLUGIN_SOURCE_DIR" to source.toString(),
                    "HARDENING_RELEASE_URL" to releaseUrl(server),
                ),
            )

            assertEquals(2, result.exitCode)
            assertContains(result.output, "checksum mismatch")
            assertTrue(Files.notExists(source.resolve("source-build-ran")))
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun `interrupted release download falls back to source and preserves interruption`() {
        val requestStarted = CountDownLatch(1)
        val releaseResponse = CountDownLatch(1)
        val sourceArchive = portableArchive("source-plugin")
        val source = sourceProject(sourceArchive)
        val server = server { _ ->
            requestStarted.countDown()
            releaseResponse.await()
        }
        val result = AtomicReference<Int?>()
        val failure = AtomicReference<Throwable?>()
        val interrupted = AtomicBoolean(false)
        val thread = Thread {
            try {
                result.set(
                    runLauncherInProcess(
                        listOf("--project-dir", consumerProject().toString(), "--", "tasks"),
                        mapOf(
                            "ANDROID_SDK_ROOT" to androidSdk().toString(),
                            "HARDENING_CACHE_HOME" to temporary.resolve("interrupted-fallback-cache").toString(),
                            "HARDENING_PLUGIN_SOURCE_DIR" to source.toString(),
                            "HARDENING_RELEASE_URL" to releaseUrl(server),
                            "HARDENING_ARGUMENT_LOG" to temporary.resolve("interrupted-fallback-args.txt").toString(),
                        ),
                    ),
                )
            } catch (thrown: Throwable) {
                failure.set(thrown)
            } finally {
                interrupted.set(Thread.currentThread().isInterrupted)
            }
        }
        try {
            thread.start()
            assertTrue(requestStarted.await(10, TimeUnit.SECONDS), "release request did not start")
            thread.interrupt()
            thread.join(TimeUnit.SECONDS.toMillis(15))

            assertTrue(!thread.isAlive, "interrupted launcher did not complete")
            assertEquals(null, failure.get())
            assertEquals(0, result.get())
            assertTrue(interrupted.get())
            assertTrue(source.resolve("source-build-ran").toFile().exists())
        } finally {
            releaseResponse.countDown()
            server.stop(0)
        }
    }

    @Test
    fun `archive entry traversal that aliases a prior path is rejected`() {
        val archive = rawZip(
            "SHA256SUMS" to "unused".encodeToByteArray(),
            markerPath() to "plugin".encodeToByteArray(),
            "repository/../${markerPath().removePrefix("repository/")}" to "plugin".encodeToByteArray(),
        )
        val cache = temporary.resolve("traversal-cache")
        cache.createDirectories()

        val failure = assertLauncherFailure {
            installArchive(archive, cache)
        }
        assertEquals("HardeningLauncher\$LauncherFailure", failure.javaClass.name)
        assertContains(failure.message.orEmpty(), "portable archive contains unsafe entry")
    }

    @Test
    fun `archive exact duplicate entries are rejected`() {
        val archive = rawZip(
            "SHA256SUMS" to "unused".encodeToByteArray(),
            markerPath() to "plugin".encodeToByteArray(),
            markerPath() to "plugin".encodeToByteArray(),
        )
        val cache = temporary.resolve("exact-duplicate-cache")
        cache.createDirectories()

        val failure = assertLauncherFailure {
            installArchive(archive, cache)
        }
        assertEquals("HardeningLauncher\$LauncherFailure", failure.javaClass.name)
        assertContains(failure.message.orEmpty(), "portable archive contains duplicate entry")
    }

    @Test
    fun `archive normalized path aliases are rejected`() {
        val marker = markerPath()
        val archive = rawZip(
            "SHA256SUMS" to "unused".encodeToByteArray(),
            marker to "plugin".encodeToByteArray(),
            marker.replace("repository/", "repository//") to "plugin".encodeToByteArray(),
        )
        val cache = temporary.resolve("normalized-duplicate-cache")
        cache.createDirectories()

        val failure = assertLauncherFailure {
            installArchive(archive, cache)
        }
        assertEquals("HardeningLauncher\$LauncherFailure", failure.javaClass.name)
        assertContains(failure.message.orEmpty(), "portable archive contains duplicate entry")
    }

    private fun consumerProject(
        wrapperProperties: String = "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.13-bin.zip\n",
    ): Path = temporary.resolve("consumer-${System.nanoTime()}").also { project ->
        project.resolve("gradle/wrapper").createDirectories()
        project.resolve("gradle/wrapper/gradle-wrapper.properties").writeText(wrapperProperties)
        val wrapper = project.resolve("gradlew")
        wrapper.writeText("#!/bin/sh\nprintf '%s\\n' \"\$@\" > \"\$HARDENING_ARGUMENT_LOG\"\n")
        Files.setPosixFilePermissions(
            wrapper,
            setOf(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE,
            ),
        )
    }

    private fun androidSdk(): Path = temporary.resolve("android-sdk").also { sdk ->
        sdk.resolve("build-tools/35.0.0").createDirectories()
        sdk.resolve("platform-tools").createDirectories()
    }

    private fun cachedRepository(cache: Path) {
        val versionRoot = cache.resolve("1.3.0")
        val marker = versionRoot.resolve(markerPath())
        marker.parent.createDirectories()
        marker.writeText("plugin")
        versionRoot.resolve("SHA256SUMS").writeText("${sha256(marker)}  ${versionRoot.relativize(marker)}\n")
    }

    private fun sourceProject(archive: Path): Path = temporary.resolve("source-${System.nanoTime()}").also { source ->
        source.createDirectories()
        source.resolve("build.gradle.kts").writeText("// source fallback fixture\n")
        val wrapper = source.resolve("gradlew")
        wrapper.writeText(
            "#!/bin/sh\n" +
                "set -eu\n" +
                "touch source-build-ran\n" +
                "echo build >> source-build.log\n" +
                "sleep 1\n" +
                "mkdir -p build/distributions\n" +
                "cp \"${archive}\" \"build/distributions/hardening-gradle-plugin-1.3.0-portable-maven.zip\"\n",
        )
        Files.setPosixFilePermissions(
            wrapper,
            setOf(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE,
            ),
        )
    }

    private fun portableArchive(content: String): Path = temporary.resolve("portable-${System.nanoTime()}.zip").also { archive ->
        val marker = markerPath()
        val bytes = content.encodeToByteArray()
        ZipOutputStream(Files.newOutputStream(archive)).use { output ->
            output.putNextEntry(ZipEntry("SHA256SUMS"))
            output.write("${sha256(bytes)}  $marker\n".encodeToByteArray())
            output.closeEntry()
            output.putNextEntry(ZipEntry(marker))
            output.write(bytes)
            output.closeEntry()
        }
    }

    private fun rawZip(vararg entries: Pair<String, ByteArray>): Path =
        temporary.resolve("raw-${System.nanoTime()}.zip").also { archive ->
            val bytes = ByteArrayOutputStream()
            DataOutputStream(bytes).use { output ->
                entries.forEach { (name, content) ->
                    val nameBytes = name.encodeToByteArray()
                    val checksum = CRC32().apply { update(content) }.value
                    writeIntLe(output, 0x04034b50L)
                    writeShortLe(output, 20)
                    writeShortLe(output, 0)
                    writeShortLe(output, 0)
                    writeShortLe(output, 0)
                    writeShortLe(output, 0)
                    writeIntLe(output, checksum)
                    writeIntLe(output, content.size.toLong())
                    writeIntLe(output, content.size.toLong())
                    writeShortLe(output, nameBytes.size)
                    writeShortLe(output, 0)
                    output.write(nameBytes)
                    output.write(content)
                }
            }
            Files.write(archive, bytes.toByteArray())
        }

    private fun writeShortLe(output: DataOutputStream, value: Int) {
        output.writeByte(value and 0xff)
        output.writeByte(value ushr 8 and 0xff)
    }

    private fun writeIntLe(output: DataOutputStream, value: Long) {
        output.writeByte(value.toInt() and 0xff)
        output.writeByte(value.toInt() ushr 8 and 0xff)
        output.writeByte(value.toInt() ushr 16 and 0xff)
        output.writeByte(value.toInt() ushr 24 and 0xff)
    }

    private fun markerPath(): String =
        "repository/com/holin/android/hardening/hardening-gradle-plugin/1.3.0/" +
            "hardening-gradle-plugin-1.3.0.jar"

    private fun server(handler: (com.sun.net.httpserver.HttpExchange) -> Unit): HttpServer =
        HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0).also { server ->
            server.createContext("/", handler)
            server.start()
        }

    private fun releaseUrl(server: HttpServer): String = "http://127.0.0.1:${server.address.port}/release.zip"

    private fun fakeJava(versionOutput: String): FakeJava {
        val bin = temporary.resolve("fake-java-${System.nanoTime()}/bin")
        bin.createDirectories()
        val sourceLaunchMarker = temporary.resolve("source-launch-${System.nanoTime()}")
        val windows = System.getProperty("os.name").startsWith("Windows", true)
        val java = bin.resolve(if (windows) "java.cmd" else "java")
        if (windows) {
            java.writeText(
                "@echo off\r\n" +
                    "if \"%~1\"==\"-version\" (\r\n" +
                    "    echo $versionOutput 1>&2\r\n" +
                    "    exit /b 0\r\n" +
                    ")\r\n" +
                    "type nul > \"%HARDENING_SOURCE_LAUNCH_MARKER%\"\r\n" +
                    "exit /b 97\r\n",
            )
        } else {
            java.writeText(
                "#!/bin/sh\n" +
                    "if [ \"\${1-}\" = \"-version\" ]; then\n" +
                    "    printf '%s\\n' '$versionOutput' >&2\n" +
                    "    exit 0\n" +
                    "fi\n" +
                    ": > \"\$HARDENING_SOURCE_LAUNCH_MARKER\"\n" +
                    "exit 97\n",
            )
            Files.setPosixFilePermissions(
                java,
                setOf(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE,
                ),
            )
        }
        return FakeJava(bin, sourceLaunchMarker)
    }

    private fun powerShellAvailable(): Boolean = try {
        ProcessBuilder("pwsh", "-NoProfile", "-Command", "exit 0")
            .start()
            .waitFor() == 0
    } catch (_: java.io.IOException) {
        false
    }

    private fun runLauncherInProcess(arguments: List<String>, environment: Map<String, String>): Int {
        val launcher = launcherClass()
        val run = launcher.getDeclaredMethod("run", List::class.java, Map::class.java)
        run.isAccessible = true
        return run.invoke(null, arguments, environment) as Int
    }

    private fun installArchive(archive: Path, cache: Path) {
        val launcher = launcherClass()
        val install = launcher.getDeclaredMethod("installArchive", Path::class.java, Path::class.java, Path::class.java)
        install.isAccessible = true
        install.invoke(null, archive, cache.resolve("1.3.0"), cache)
    }

    private fun assertLauncherFailure(action: () -> Unit): Throwable =
        requireNotNull(assertFailsWith<InvocationTargetException> { action() }.targetException)

    private fun downloadRelease(cache: Path, url: String, checksum: String): Path {
        return requireNotNull(downloadReleaseOrNull(cache, url, checksum)) { "download result did not include an archive" }
    }

    private fun downloadReleaseOrNull(cache: Path, url: String, checksum: String): Path? {
        val launcher = launcherClass()
        val download = launcher.getDeclaredMethod("downloadRelease", Path::class.java, URI::class.java, String::class.java)
        download.isAccessible = true
        val result = download.invoke(null, cache, URI.create(url), checksum)
        val archive = result.javaClass.getDeclaredMethod("archive")
        archive.isAccessible = true
        return archive.invoke(result) as Path?
    }

    private fun launcherClass(): Class<*> {
        val root = Path.of("").toAbsolutePath().normalize()
        val classes = temporary.resolve("launcher-classes")
        classes.createDirectories()
        val compiler = requireNotNull(ToolProvider.getSystemJavaCompiler()) { "a JDK compiler is required" }
        assertEquals(
            0,
            compiler.run(
                null,
                null,
                null,
                "-d",
                classes.toString(),
                root.resolve("bootstrap/HardeningLauncher.java").toString(),
            ),
        )
        return URLClassLoader(arrayOf(classes.toUri().toURL()), javaClass.classLoader).loadClass("HardeningLauncher")
    }

    private fun runLauncher(arguments: List<String>, environment: Map<String, String>): ProcessResult {
        val root = Path.of("").toAbsolutePath().normalize()
        val java = Path.of(System.getProperty("java.home"), "bin", "java")
        val command = listOf(java.toString(), root.resolve("bootstrap/HardeningLauncher.java").toString()) + arguments
        val process = ProcessBuilder(command)
            .directory(root.toFile())
            .redirectErrorStream(true)
            .also { builder -> builder.environment().putAll(environment) }
            .start()
        val output = process.inputStream.bufferedReader().use { it.readText() }
        return ProcessResult(process.waitFor(), output)
    }

    private fun sha256(path: Path): String = sha256(Files.readAllBytes(path))

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { byte -> "%02x".format(byte) }

    private data class ProcessResult(val exitCode: Int, val output: String)

    private data class FakeJava(val bin: Path, val sourceLaunchMarker: Path)
}
