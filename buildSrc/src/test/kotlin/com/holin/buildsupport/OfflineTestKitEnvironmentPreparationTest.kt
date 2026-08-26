package com.holin.buildsupport

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class OfflineTestKitEnvironmentPreparationTest {
    @TempDir
    lateinit var temporary: Path

    @Test
    fun `offline TestKit contract pins the reviewed Gradle distributions`() {
        assertEquals(
            listOf(
                GradleDistributionSpec(
                    "8.10.2",
                    "31c55713e40233a8303827ceb42ca48a47267a0ad4bab9177123121e71524c26",
                ),
                GradleDistributionSpec(
                    "8.11.1",
                    "f397b287023acdba1e9f6fc5ea72d22dd63669d59ed4a289a29b1a76eee151c6",
                ),
                GradleDistributionSpec(
                    "8.13",
                    "20f1b1176237254a6fc204d8434196fa11a4cfb387567519c61556e8710aed78",
                ),
            ),
            OfflineTestKitEnvironmentContract.gradleDistributions,
        )
        assertEquals(
            "./gradlew prepareOfflineTestKitEnvironment",
            OfflineTestKitEnvironmentContract.onlinePreparationCommand,
        )
    }

    @Test
    fun `offline preparation aggregates missing distributions and unresolved rows deterministically`() {
        val gradleUserHome = temporary.resolve("gradle-user-home")
        val incomplete = gradleUserHome.resolve("holin-hardening/distributions/8.13/gradle-8.13")
        Files.createDirectories(incomplete)
        val provisioner = GradleDistributionProvisioner(
            DistributionDownloader { _, _ -> error("offline mode must not download") },
        )
        val preparer = OfflineTestKitEnvironmentPreparer(provisioner)
        val first = failureMessage(
            preparer,
            gradleUserHome,
            listOf(distribution("8.13"), distribution("8.10.2")),
            listOf(
                OfflineMatrixPreparation("z-row") { error("missing z") },
                OfflineMatrixPreparation("a-row") { error("missing a") },
            ),
        )
        val second = failureMessage(
            preparer,
            gradleUserHome,
            listOf(distribution("8.10.2"), distribution("8.13")),
            listOf(
                OfflineMatrixPreparation("a-row") { error("missing a") },
                OfflineMatrixPreparation("z-row") { error("missing z") },
            ),
        )

        assertEquals(first, second)
        assertContains(first, "Gradle 8.10.2")
        assertContains(first, "Gradle 8.13")
        assertContains(first, "incomplete")
        assertContains(first, "matrix a-row: missing a")
        assertContains(first, "matrix z-row: missing z")
        assertContains(first, OfflineTestKitEnvironmentContract.onlinePreparationCommand)
        assertTrue(first.indexOf("Gradle 8.10.2") < first.indexOf("Gradle 8.13"))
        assertTrue(first.indexOf("matrix a-row") < first.indexOf("matrix z-row"))
    }

    @Test
    fun `offline preparation never invokes the distribution downloader`() {
        var downloads = 0
        val preparer = OfflineTestKitEnvironmentPreparer(
            GradleDistributionProvisioner(
                DistributionDownloader { _, _ -> downloads++ },
            ),
        )

        assertFailsWith<IllegalStateException> {
            preparer.prepare(
                temporary.resolve("gradle-user-home"),
                listOf(distribution("8.10.2")),
                emptyList(),
                true,
            )
        }

        assertEquals(0, downloads)
    }

    @Test
    fun `environment validation aggregates actionable failures without changing the SDK`() {
        val sdk = temporary.resolve("android-sdk")
        Files.createDirectories(sdk)
        val marker = sdk.resolve("marker.txt")
        Files.writeString(marker, "unchanged")

        val failure = assertFailsWith<IllegalStateException> {
            HardeningEnvironmentValidator.requireValid(
                HardeningEnvironmentSnapshot("8.9", 16, sdk),
            )
        }

        assertContains(failure.message.orEmpty(), "Gradle 8.10+")
        assertContains(failure.message.orEmpty(), "JDK 17+")
        assertContains(failure.message.orEmpty(), "platform-tools")
        assertContains(failure.message.orEmpty(), "build-tools")
        assertEquals("unchanged", Files.readString(marker))
        assertEquals(
            listOf("marker.txt"),
            Files.list(sdk).use { paths -> paths.map { it.fileName.toString() }.sorted().toList() },
        )
    }

    private fun failureMessage(
        preparer: OfflineTestKitEnvironmentPreparer,
        gradleUserHome: Path,
        distributions: List<GradleDistributionSpec>,
        rows: List<OfflineMatrixPreparation>,
    ): String = assertFailsWith<IllegalStateException> {
        preparer.prepare(gradleUserHome, distributions, rows, true)
    }.message.orEmpty()

    private fun distribution(version: String): GradleDistributionSpec =
        GradleDistributionSpec(version, "0".repeat(64))
}
