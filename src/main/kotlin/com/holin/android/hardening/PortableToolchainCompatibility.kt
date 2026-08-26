package com.holin.android.hardening

import org.gradle.api.JavaVersion
import org.gradle.api.Project
import org.gradle.util.GradleVersion

internal data class ToolchainVersions(
    val gradle: String,
    val javaFeature: Int,
    val androidGradlePlugin: String,
    val kotlinAndroidPlugin: String,
)

internal object PortableToolchainCompatibility {
    const val GRADLE_VERSION = "8.10"
    const val JAVA_FEATURE = 17
    const val AGP_VERSION = "8.8.0"
    const val KOTLIN_VERSION = "2.3.0"

    fun verify(actual: ToolchainVersions) {
        requireVersion("Gradle", actual.gradle, GRADLE_VERSION)
        require(actual.javaFeature >= JAVA_FEATURE) {
            "JDK version is incompatible: actual=${actual.javaFeature}, minimum=$JAVA_FEATURE"
        }
        requireVersion("Android Gradle Plugin", actual.androidGradlePlugin, AGP_VERSION)
        requireVersion("Kotlin Android plugin", actual.kotlinAndroidPlugin, KOTLIN_VERSION)
    }

    private fun requireVersion(component: String, actual: String, minimum: String) {
        val actualVersion = actual.takeIf(VERSION::matches)?.let(GradleVersion::version)
        require(actualVersion != null && actualVersion >= GradleVersion.version(minimum)) {
            "$component version is incompatible: actual=$actual, minimum=$minimum"
        }
    }

    private val VERSION = Regex("[0-9]+\\.[0-9]+(?:\\.[0-9]+)?(?:[-.][0-9A-Za-z]+)*")
}

internal object ProjectToolchainInspector {
    fun inspect(project: Project): ToolchainVersions = ToolchainVersions(
        project.gradle.gradleVersion,
        JavaVersion.current().majorVersion.toInt(),
        androidGradlePluginVersion(project),
        kotlinAndroidPluginVersion(project),
    )

    private fun androidGradlePluginVersion(project: Project): String {
        val plugin = project.plugins.findPlugin("com.android.application")
            ?: return "not applied"
        return runCatching {
            Class.forName("com.android.builder.model.Version", true, plugin.javaClass.classLoader)
                .getField("ANDROID_GRADLE_PLUGIN_VERSION")
                .get(null)
                .toString()
        }.getOrElse { pluginVersionFromManifest(plugin) }
    }

    private fun kotlinAndroidPluginVersion(project: Project): String {
        val plugin = project.plugins.findPlugin("org.jetbrains.kotlin.android")
            ?: return "not applied"
        return runCatching {
            Class.forName(
                "org.jetbrains.kotlin.gradle.plugin.KotlinPluginWrapperKt",
                true,
                plugin.javaClass.classLoader,
            ).getMethod("getKotlinPluginVersion", Project::class.java)
                .invoke(null, project)
                .toString()
        }.getOrElse { pluginVersionFromManifest(plugin) }
    }

    private fun pluginVersionFromManifest(plugin: Any): String {
        val candidates = generateSequence(plugin.javaClass as Class<*>?) { type -> type.superclass }
        val raw = candidates.mapNotNull { type -> type.`package`?.implementationVersion }.firstOrNull()
            ?: return "unavailable (${plugin.javaClass.name})"
        return SEMANTIC_VERSION.find(raw)?.value ?: raw
    }

    private val SEMANTIC_VERSION = Regex("[0-9]+\\.[0-9]+\\.[0-9]+")
}
