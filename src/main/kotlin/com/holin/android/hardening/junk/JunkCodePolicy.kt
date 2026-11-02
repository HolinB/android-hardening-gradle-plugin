package com.holin.android.hardening.junk

import com.holin.android.hardening.state.StrictJson
import groovy.json.JsonOutput
import groovy.json.JsonSlurper

/** Counts are totals for one application variant, not counts per package. */
data class JunkCodePolicy(
    val enabled: Boolean = true,
    val packageCount: Int = 4,
    val classCount: Int = 100,
    val activityCount: Int = 8,
    val methodCountPerClass: Int = 10,
    val drawableCount: Int = 40,
    val stringCount: Int = 40,
) {
    init {
        listOf(packageCount, classCount, activityCount, methodCountPerClass, drawableCount, stringCount)
            .forEach { require(it >= 0) { "junkCode counts must be non-negative" } }
        val classes = classCount.toLong() + activityCount
        require(classes == 0L || packageCount > 0) { "junkCode.packageCount must be positive when generating classes" }
        require(classes <= Int.MAX_VALUE && classes * (methodCountPerClass.toLong() + 1) + activityCount <= Int.MAX_VALUE) {
            "junkCode total class or method count overflows"
        }
        require(methodCountPerClass <= 65533) { "junkCode methods exceed the JVM per-class limit" }
        require(listOf(activityCount, drawableCount, stringCount).all { it <= 65535 }) {
            "junkCode resources exceed the Android per-type entry limit"
        }
    }

    fun encode(): String = JsonOutput.toJson(toMap())

    internal fun toMap(): Map<String, Any> = linkedMapOf(
        "enabled" to enabled, "packageCount" to packageCount, "classCount" to classCount,
        "activityCount" to activityCount, "methodCountPerClass" to methodCountPerClass,
        "drawableCount" to drawableCount, "stringCount" to stringCount,
    )

    companion object {
        const val GENERATOR_VERSION = 2

        fun decode(text: String): JunkCodePolicy {
            StrictJson.validateDocument(text)
            val data = JsonSlurper().parseText(text) as? Map<*, *> ?: error("junkCode policy must be an object")
            fun count(key: String): Int {
                val value = data[key] as? Number ?: error("junkCode.$key must be an integer")
                require(value.toString() == value.toInt().toString()) { "junkCode.$key must be an integer in range" }
                return value.toInt()
            }
            return JunkCodePolicy(
                data["enabled"] as? Boolean ?: error("junkCode.enabled must be a boolean"),
                count("packageCount"), count("classCount"), count("activityCount"),
                count("methodCountPerClass"), count("drawableCount"), count("stringCount"),
            )
        }
    }
}
