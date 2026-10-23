package com.holin.android.hardening.runtime

import com.holin.android.hardening.artifact.BundleEntryReplacement
import com.holin.android.hardening.artifact.BundleSemanticVerifier
import com.holin.android.hardening.resources.ControlledAssets
import com.holin.android.hardening.state.Sha256
import com.holin.android.hardening.state.StrictJson
import groovy.json.JsonSlurper

data class RuntimeClosure(val policy: RuntimeProtectionPolicy, val strings: Set<String>, val assets: Map<String, String>, val helper: String, val images: Set<String> = emptySet(), val stringAnalysis: Map<String, Any> = emptyMap()) {
    companion object {
        fun read(text: String): RuntimeClosure {
            StrictJson.validateDocument(text)
            val p = JsonSlurper().parseText(text) as Map<*, *>
            require(p["schemaVersion"] == 1)
            val policy = RuntimeProtectionPolicy.decode(p["policy"] as String)
            val strings = (p["strings"] as List<*>).map { it as String }.toSet()
            val assets = (p["assets"] as Map<*, *>).entries.associate { it.key as String to it.value as String }
            require(policy.selectedStrings.containsAll(strings) && policy.assetPaths.containsAll(assets.keys))
            require(assets.values.all { Regex("[a-f0-9]{64}").matches(it) })
            val images = (p["images"] as? List<*>)?.map { it as String }?.toSet().orEmpty()
            require(images.all(policy.images::accepts))
            @Suppress("UNCHECKED_CAST")
            val stringAnalysis = p["stringAnalysis"] as? Map<String, Any> ?: emptyMap()
            return RuntimeClosure(policy, strings, assets, p["helper"] as String, images, stringAnalysis)
        }
    }
}

data class RuntimeVerificationScope(val stringIds: Set<Int>, val assetPaths: Set<String>, val key: ByteArray,
    val images: Map<String, RuntimeImageRecord> = emptyMap())

object RuntimeAssetContainers {
    fun transform(entries: Map<String, ByteArray>, formats: List<BundleEntryReplacement>, closure: RuntimeClosure, key: ByteArray): List<BundleEntryReplacement> =
        transform(entries, closure, key, byteArrayOf())

    fun transform(entries: Map<String, ByteArray>, closure: RuntimeClosure, key: ByteArray, salt: ByteArray): List<BundleEntryReplacement> {
        return closure.assets.toSortedMap().map { (path, hash) ->
            val zipPath = "base/assets/$path"
            val original = requireNotNull(entries[zipPath]) { "runtime source asset disappeared: $path" }
            require(Sha256.hex(original) == hash) { "runtime source asset differs from the owned bytecode closure: $path" }
            val outputPath = "base/assets/" + RuntimeEnvelope.assetPath(path, key)
            require(outputPath !in entries) { "runtime asset output already exists" }
            val encrypted = RuntimeEnvelope.encrypt(original, key, "asset:$path:${Sha256.hex(salt)}")
            require(RuntimeEnvelope.decrypt(encrypted, key).contentEquals(original)) { "runtime asset round trip failed" }
            BundleEntryReplacement(zipPath, outputPath, encrypted, BundleSemanticVerifier.ASSET_RUNTIME_EQUIVALENCE)
        }
    }

    fun verify(oldPath: String, newPath: String, before: ByteArray, after: ByteArray, scope: RuntimeVerificationScope, salt: ByteArray) {
        require(oldPath.startsWith("base/assets/"))
        val path = oldPath.removePrefix("base/assets/")
        require(path in scope.assetPaths && newPath == "base/assets/" + RuntimeEnvelope.assetPath(path, scope.key))
        val restored = RuntimeEnvelope.decrypt(after, scope.key)
        require(restored.contentEquals(before)) { "runtime asset payload differs from its original bytes" }
    }
}
