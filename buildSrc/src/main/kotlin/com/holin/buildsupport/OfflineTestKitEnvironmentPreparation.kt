package com.holin.buildsupport

import java.nio.file.Files
import java.nio.file.Path
import org.gradle.util.GradleVersion

object OfflineTestKitEnvironmentContract {
    val gradleDistributions = listOf(
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
    )
    const val onlinePreparationCommand = "./gradlew prepareOfflineTestKitEnvironment"
}

data class OfflineMatrixPreparation(
    val id: String,
    val resolve: () -> Unit,
)

data class PreparedOfflineTestKitEnvironment(
    val gradleHomes: Map<String, Path>,
)

class OfflineTestKitEnvironmentPreparer(
    private val provisioner: GradleDistributionProvisioner,
) {
    fun prepare(
        gradleUserHome: Path,
        distributions: List<GradleDistributionSpec>,
        rows: List<OfflineMatrixPreparation>,
        offline: Boolean,
    ): PreparedOfflineTestKitEnvironment {
        val homes = linkedMapOf<String, Path>()
        val failures = mutableListOf<String>()
        distributions.sortedBy(GradleDistributionSpec::version).forEach { distribution ->
            runCatching {
                provisioner.ensure(gradleUserHome, distribution, offline)
            }.onSuccess { home ->
                homes[distribution.version] = home
            }.onFailure { failure ->
                failures += "Gradle ${distribution.version}: ${failure.description()}"
            }
        }
        rows.sortedBy(OfflineMatrixPreparation::id).forEach { row ->
            runCatching(row.resolve).onFailure { failure ->
                failures += "matrix ${row.id}: ${failure.description()}"
            }
        }
        check(failures.isEmpty()) {
            failures.joinToString(
                "\n- ",
                "Offline TestKit environment is incomplete:\n- ",
                "\nRun the online preparation command exactly once:\n" +
                    OfflineTestKitEnvironmentContract.onlinePreparationCommand,
            )
        }
        return PreparedOfflineTestKitEnvironment(homes.toMap())
    }

    private fun Throwable.description(): String = message?.takeIf(String::isNotBlank)
        ?: javaClass.simpleName
}

data class HardeningEnvironmentSnapshot(
    val gradleVersion: String,
    val javaFeatureVersion: Int,
    val androidSdk: Path?,
)

object HardeningEnvironmentValidator {
    fun requireValid(environment: HardeningEnvironmentSnapshot) {
        val failures = failures(environment)
        check(failures.isEmpty()) {
            failures.joinToString("\n- ", "Hardening environment check failed:\n- ")
        }
    }

    fun failures(environment: HardeningEnvironmentSnapshot): List<String> = buildList {
        val currentGradle = runCatching { GradleVersion.version(environment.gradleVersion) }.getOrNull()
        if (currentGradle == null || currentGradle < MINIMUM_GRADLE) {
            add("Gradle 8.10+ is required; found ${environment.gradleVersion}")
        }
        if (environment.javaFeatureVersion < 17) {
            add("JDK 17+ is required; found Java ${environment.javaFeatureVersion}")
        }
        val sdk = environment.androidSdk
        when {
            sdk == null -> add("Android SDK is not configured; set ANDROID_SDK_ROOT or ANDROID_HOME")
            !Files.isDirectory(sdk) -> add("Android SDK directory does not exist: $sdk")
            else -> {
                if (!Files.isDirectory(sdk.resolve("platform-tools"))) {
                    add("Android SDK platform-tools are missing under $sdk")
                }
                val buildTools = sdk.resolve("build-tools")
                val hasBuildTools = Files.isDirectory(buildTools) && Files.list(buildTools).use { paths ->
                    paths.anyMatch(Files::isDirectory)
                }
                if (!hasBuildTools) {
                    add("Android SDK build-tools are missing under $sdk")
                }
            }
        }
    }

    private val MINIMUM_GRADLE = GradleVersion.version("8.10")
}
