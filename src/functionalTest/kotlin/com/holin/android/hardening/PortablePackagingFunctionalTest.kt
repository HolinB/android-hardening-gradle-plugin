package com.holin.android.hardening

import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipFile
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertFalse
import org.gradle.testkit.runner.GradleRunner

class PortablePackagingFunctionalTest {
    @Test
    fun `staging excludes a seeded legacy marker and the portable ZIP`() {
        val portableArchive = Path.of(
            requireNotNull(System.getProperty("portable.plugin.archive")) {
                "portable.plugin.archive test property is required"
            },
        ).toAbsolutePath().normalize()
        val buildLogic = portableArchive.parent.parent.parent
        val oldMarker = buildLogic.resolve(
            "build/portable/repository/com/legacy/vendor/android/hardening/" +
                "com.legacy.vendor.android.hardening.gradle.plugin/1.1.0/" +
                "com.legacy.vendor.android.hardening.gradle.plugin-1.1.0.pom",
        )
        oldMarker.parent.createDirectories()
        oldMarker.writeText("<project><legacy>seeded</legacy></project>\n")

        GradleRunner.create()
            .withProjectDir(buildLogic.toFile())
            .withArguments(
                "--offline",
                "--gradle-user-home",
                requireNotNull(System.getProperty("portable.gradle.user.home")),
                "--stacktrace",
                "packagePortableHardeningPlugin",
            )
            .build()

        val staging = buildLogic.resolve("build/portable/staging")
        assertFalse(
            Files.exists(
                staging.resolve(
                    "repository/com/legacy/vendor/android/hardening/" +
                        "com.legacy.vendor.android.hardening.gradle.plugin/1.1.0/" +
                        "com.legacy.vendor.android.hardening.gradle.plugin-1.1.0.pom",
                ),
            ),
            "legacy marker reached staging",
        )
        val archive = buildLogic.resolve("build/distributions/hardening-gradle-plugin-1.2.0-portable-maven.zip")
        ZipFile(archive.toFile()).use { zip ->
            assertFalse(
                zip.entries().asSequence().any { entry -> entry.name.contains("com/legacy/vendor/android/hardening") },
                "legacy marker reached portable ZIP",
            )
        }
    }
}
