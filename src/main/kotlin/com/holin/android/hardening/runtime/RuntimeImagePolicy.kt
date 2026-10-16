package com.holin.android.hardening.runtime

import java.nio.file.FileSystems
import java.nio.file.Path

data class RuntimeImagePolicy(
    val enabled: Boolean = false,
    val includes: Set<String> = setOf("drawable/*"),
    val excludes: Set<String> = emptySet(),
    val minimumCoverage: Double = 0.0,
) {
    init {
        require(minimumCoverage.isFinite() && minimumCoverage in 0.0..1.0)
        require(includes.isNotEmpty())
        (includes + excludes).forEach { pattern ->
            require(pattern.startsWith("drawable/") && ".." !in pattern && '\\' !in pattern)
            FileSystems.getDefault().getPathMatcher("glob:$pattern")
        }
    }
    fun accepts(name: String): Boolean = enabled && includes.any { matches(it, name) } && excludes.none { matches(it, name) }
    private fun matches(pattern: String, name: String) = FileSystems.getDefault().getPathMatcher("glob:$pattern").matches(Path.of("drawable/$name"))
    fun values(): Map<String, Any> = mapOf("enabled" to enabled, "includes" to includes.sorted(), "excludes" to excludes.sorted(), "minimumCoverage" to minimumCoverage)
    companion object {
        fun read(value: Map<*, *>): RuntimeImagePolicy = RuntimeImagePolicy(value["enabled"] as Boolean,
            (value["includes"] as List<*>).map { it as String }.toSet(), (value["excludes"] as List<*>).map { it as String }.toSet(),
            (value["minimumCoverage"] as Number).toDouble())
    }
}
