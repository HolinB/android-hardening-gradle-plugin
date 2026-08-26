package com.holin.android.hardening

internal object HardeningWiringGate {
    fun isEnabled(projectProperties: Map<String, String>): Boolean =
        projectProperties[PROPERTY_NAME]?.toBoolean() == true

    fun isSelected(variantName: String, includedVariants: Set<String>): Boolean =
        variantName in includedVariants

    fun forbiddenTaskNames(taskNames: Collection<String>): List<String> = taskNames
        .filter { requested ->
            val taskName = RequestedTask.parse(requested).name
            FORBIDDEN_TASK_CATEGORIES.any { category -> hasLeadingCategory(taskName, category) }
        }
        .distinct()
        .sorted()

    private fun hasLeadingCategory(taskName: String, category: String): Boolean {
        if (!taskName.startsWith(category, true)) return false
        return taskName.length == category.length || !taskName[category.length].isLowerCase()
    }

    fun isHardeningTaskRequested(
        variantName: String,
        requestedTasks: List<String>,
        projectPath: String? = null,
    ): Boolean = requestedTasks.any { requested ->
        val task = RequestedTask.parse(requested)
        task.belongsTo(projectPath) && isHardeningTaskName(task.name, variantName)
    }

    fun conflictingProjectArtifactTasks(
        requestedTasks: List<String>,
        includedVariants: Set<String>,
        projectPath: String,
    ): List<String> = requestedTasks.filter { requested ->
        val task = RequestedTask.parse(requested)
        task.belongsTo(projectPath) &&
            isArtifactProducingTask(task.name) &&
            includedVariants.none { variant -> isHardeningTaskName(task.name, variant) }
    }

    fun isHardeningRunRequested(
        variantName: String,
        requestedTasks: List<String>,
        projectPath: String? = null,
    ): Boolean {
        val runTaskName = "hardeningRun${HardeningNames.taskSuffix(variantName)}"
        return requestedTasks.any { requested ->
            val task = RequestedTask.parse(requested)
            task.belongsTo(projectPath) && task.name.equals(runTaskName, ignoreCase = true)
        }
    }

    private fun isArtifactProducingTask(taskName: String): Boolean =
        listOf("assemble", "bundle", "install", "package")
            .any { prefix -> taskName.startsWith(prefix, ignoreCase = true) } ||
            taskName.contains("upload", ignoreCase = true) ||
            taskName.contains("publish", ignoreCase = true)

    private fun isHardeningTaskName(taskName: String, variantName: String): Boolean {
        val suffix = HardeningNames.taskSuffix(variantName)
        return listOf(
            "prepareHardening$suffix",
            "auditHardening$suffix",
            "verifyHardening$suffix",
            "archiveHardening$suffix",
            "hardeningBundle$suffix",
            "hardeningAssemble$suffix",
            "captureHardeningBaseline$suffix",
            "compareHardening$suffix",
            "compareExternalHardening$suffix",
            "hardeningRun$suffix",
            "benchmarkHardening$suffix",
            "generateHardening${suffix}R8Rules",
            "generateHardening${suffix}CodeMapping",
            "rewriteHardening${suffix}Bundle",
            "signHardening${suffix}Bundle",
            "validateHardening${suffix}Bundle",
            "assembleHardening${suffix}UniversalApk",
            "assembleOrdinary${suffix}UniversalApk",
        ).any { registeredName -> registeredName.equals(taskName, ignoreCase = true) }
    }

    private data class RequestedTask(val projectPath: String?, val name: String) {
        fun belongsTo(targetProjectPath: String?): Boolean =
            targetProjectPath == null || projectPath == null || projectPath == targetProjectPath

        companion object {
            fun parse(requested: String): RequestedTask {
                val separator = requested.lastIndexOf(':')
                if (separator < 0) return RequestedTask(projectPath = null, name = requested)
                val rawProjectPath = requested.substring(0, separator)
                val normalizedProjectPath = when {
                    rawProjectPath.isEmpty() -> ":"
                    rawProjectPath.startsWith(':') -> rawProjectPath
                    else -> ":$rawProjectPath"
                }
                return RequestedTask(
                    projectPath = normalizedProjectPath,
                    name = requested.substring(separator + 1),
                )
            }
        }
    }

    fun requestedBuildTypes(
        requestedTasks: List<String>,
        includedVariants: Set<String>,
        buildTypes: Set<String>,
        projectPath: String? = null,
    ): Set<String> {
        val requestedVariants = includedVariants.filter { variant ->
            isHardeningTaskRequested(variant, requestedTasks, projectPath)
        }
        return requestedVariants.mapNotNullTo(linkedSetOf()) { variant ->
            buildTypes
                .filter { buildType ->
                variant.equals(buildType, ignoreCase = true) ||
                    variant.endsWith(buildType, ignoreCase = true)
                }
                .maxByOrNull(String::length)
        }
    }

    private const val PROPERTY_NAME = "androidHardening"
    private val FORBIDDEN_TASK_CATEGORIES = setOf("upload", "publish", "install", "notify")
}
