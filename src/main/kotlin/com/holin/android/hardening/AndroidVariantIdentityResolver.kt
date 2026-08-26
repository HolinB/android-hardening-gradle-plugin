package com.holin.android.hardening

import org.gradle.api.Project
import org.gradle.api.provider.Provider

internal data class AndroidVariantIdentity(
    val namespace: String,
    val applicationId: String,
    val versionCode: Int,
    val versionName: String,
)

internal object AndroidVariantIdentityResolver {
    fun resolve(project: Project, variantName: String): AndroidVariantIdentity {
        val android = project.extensions.findByName("android")
            ?: throw IllegalStateException("Android hardening requires an Android extension for selected variant $variantName")
        val flavor = productFlavors(android)
            .filter { flavorName(it)?.let { name -> variantName.startsWith(name, ignoreCase = true) } == true }
            .maxByOrNull { requireNotNull(flavorName(it)).length }
        val defaultConfig = readValue(android, "getDefaultConfig")

        val namespace = readString(flavor, "getNamespace")
            ?: readString(android, "getNamespace")
        val applicationId = readString(flavor, "getApplicationId")
            ?: readString(defaultConfig, "getApplicationId")
        val versionCode = readInt(flavor, "getVersionCode")
            ?: readInt(defaultConfig, "getVersionCode")
        val versionName = readString(flavor, "getVersionName")
            ?: readString(defaultConfig, "getVersionName")

        require(!namespace.isNullOrBlank()) {
            "cannot resolve Android namespace for selected variant $variantName"
        }
        require(!applicationId.isNullOrBlank()) {
            "cannot resolve Android applicationId for selected variant $variantName"
        }
        require(versionCode != null && versionCode > 0) {
            "cannot resolve a positive Android versionCode for selected variant $variantName"
        }
        require(!versionName.isNullOrBlank()) {
            "cannot resolve a nonblank Android versionName for selected variant $variantName"
        }
        return AndroidVariantIdentity(namespace, applicationId, versionCode, versionName)
    }

    private fun productFlavors(android: Any): Sequence<Any> = when (val value = readValue(android, "getProductFlavors")) {
        is Iterable<*> -> value.asSequence().filterNotNull()
        is Array<*> -> value.asSequence().filterNotNull()
        else -> emptySequence()
    }

    private fun flavorName(flavor: Any): String? = readString(flavor, "getName")

    private fun readString(target: Any?, getter: String): String? = readValue(target, getter)
        ?.toString()
        ?.takeIf(String::isNotBlank)

    private fun readInt(target: Any?, getter: String): Int? = when (val value = readValue(target, getter)) {
        is Number -> value.toInt()
        is String -> value.toIntOrNull()
        else -> null
    }

    private fun readValue(target: Any?, getter: String): Any? {
        if (target == null) return null
        val raw = target.javaClass.methods
            .firstOrNull { it.name == getter && it.parameterCount == 0 }
            ?.invoke(target)
            ?: return null
        return if (raw is Provider<*>) raw.orNull else raw
    }
}
