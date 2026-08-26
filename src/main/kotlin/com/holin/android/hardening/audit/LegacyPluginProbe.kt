package com.holin.android.hardening.audit

import com.holin.android.hardening.state.Sha256
import java.nio.file.Files
import java.nio.file.Path
import org.gradle.api.Project

internal object LegacyPluginProbe {
    fun observe(
        project: Project,
        expectations: List<LegacyPluginProbeExpectation>,
    ): List<LegacyPluginObservation> {
        val applied = expectations.mapNotNull { expectation ->
            project.plugins.findPlugin(expectation.pluginId)?.let { expectation to it }
        }
        if (applied.isEmpty()) return emptyList()

        val tasks = project.tasks.toList()
        return applied.map { (expectation, plugin) ->
            val implementation = plugin.javaClass
            val artifact = implementation.protectionDomain?.codeSource?.location?.let { location ->
                runCatching { Path.of(location.toURI()).toAbsolutePath().normalize() }.getOrNull()
            }
            val matchingTasks = tasks.mapNotNull { task ->
                val classHierarchy = generateSequence(task.javaClass as Class<*>?) { type -> type.superclass }
                    .map(Class<*>::getName)
                    .toList()
                if (classHierarchy.any(expectation.taskClasses::contains)) task.name to classHierarchy else null
            }
            val extension = project.extensions.findByName(expectation.extensionName)
            LegacyPluginObservation(
                pluginId = expectation.pluginId,
                implementationClass = implementation.name,
                implementationArtifact = artifact?.fileName?.toString().orEmpty(),
                implementationSha256 = artifact?.takeIf { Files.isRegularFile(it) }?.let(Sha256::file).orEmpty(),
                extensionName = expectation.extensionName,
                extensionClass = extension?.javaClass?.name.orEmpty(),
                taskNames = matchingTasks.map { it.first }.distinct().sorted(),
                taskClasses = matchingTasks.flatMap { it.second }.distinct().sorted(),
            )
        }.sortedBy(LegacyPluginObservation::pluginId)
    }
}

internal data class LegacyPluginProbeExpectation(
    val pluginId: String,
    val extensionName: String,
    val taskClasses: Set<String>,
)
