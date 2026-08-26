package com.holin.android.hardening.similarity

import com.holin.android.hardening.state.Sha256
import com.holin.android.hardening.state.StrictJson
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.nio.file.Path

data class OwnedArtifactInventory(
    val ownedModules: Set<String>,
    val ownedDescriptors: Set<String>,
    val ordinaryOwnedResources: Map<OwnedResourceKey, OwnedResourceLocation>,
    val hardenedOwnedResources: Map<OwnedResourceKey, OwnedResourceLocation>,
) {
    init {
        require(ownedModules.isNotEmpty()) { "owned artifact inventory modules must not be empty" }
        require(ownedDescriptors.isNotEmpty()) { "owned artifact descriptors must not be empty" }
        require(ownedDescriptors.all(OWNED_DESCRIPTOR::matches)) { "owned artifact descriptors must be exact" }
        require(ordinaryOwnedResources.isNotEmpty() && ordinaryOwnedResources.keys == hardenedOwnedResources.keys) {
            "ordinary and hardened owned resource keys must be identical and nonempty"
        }
        ordinaryOwnedResources.forEach { (key, ordinary) ->
            val hardened = hardenedOwnedResources.getValue(key)
            require(ordinary.semanticHash == hardened.semanticHash) {
                "owned resource semantic hash mismatch for ${key.resourceId}:${key.qualifier}"
            }
        }
        OwnedArtifactAnalysisRequest(
            ordinaryAab = PLACEHOLDER,
            hardenedAab = PLACEHOLDER,
            ordinaryUniversalApk = PLACEHOLDER,
            hardenedUniversalApk = PLACEHOLDER,
            ownedDescriptors = ownedDescriptors,
            ordinaryOwnedResources = ordinaryOwnedResources,
            hardenedOwnedResources = hardenedOwnedResources,
        )
    }

    val ownershipSha256: String
        get() = Sha256.hex(OwnedArtifactInventoryCodec.encode(this).toByteArray(Charsets.UTF_8))

    private companion object {
        val OWNED_DESCRIPTOR = Regex("L[^;\\[\\]()]+;")
        val PLACEHOLDER = java.nio.file.Path.of("compiled-inventory-placeholder")
    }
}

data class ValidatedOwnedArtifactInventories(
    val identity: OwnedArtifactInventory,
    val analysis: OwnedArtifactInventory,
) {
    init {
        require(identity.ownedModules == analysis.ownedModules) {
            "identity and analysis owned modules must be identical"
        }
        require(identity.ownedDescriptors == analysis.ownedDescriptors) {
            "identity and analysis owned descriptors must be identical"
        }
        require(identity.ordinaryOwnedResources.keys == analysis.ordinaryOwnedResources.keys) {
            "identity and analysis ordinary resource keys must be identical"
        }
        identity.ordinaryOwnedResources.forEach { (key, identityLocation) ->
            val analysisLocation = analysis.ordinaryOwnedResources.getValue(key)
            require(identityLocation.semanticHash == analysisLocation.semanticHash) {
                "identity and analysis ordinary resource semantic hash must be identical for $key"
            }
            require(identityLocation == analysisLocation) {
                "identity and analysis ordinary resource locations must be identical for $key"
            }
        }
        require(identity.hardenedOwnedResources.keys == analysis.hardenedOwnedResources.keys) {
            "identity and analysis hardened resource keys must be identical"
        }
        identity.hardenedOwnedResources.forEach { (key, identityLocation) ->
            require(identityLocation.semanticHash == analysis.hardenedOwnedResources.getValue(key).semanticHash) {
                "identity and analysis hardened resource semantic hash must be identical for $key"
            }
        }
    }

    val identityOwnershipSha256: String
        get() = identity.ownershipSha256

    fun analysisRequest(
        ordinaryAab: Path,
        hardenedAab: Path,
        ordinaryUniversalApk: Path,
        hardenedUniversalApk: Path,
    ) = OwnedArtifactAnalysisRequest(
        ordinaryAab = ordinaryAab,
        hardenedAab = hardenedAab,
        ordinaryUniversalApk = ordinaryUniversalApk,
        hardenedUniversalApk = hardenedUniversalApk,
        ownedDescriptors = analysis.ownedDescriptors,
        ordinaryOwnedResources = analysis.ordinaryOwnedResources,
        hardenedOwnedResources = analysis.hardenedOwnedResources,
    )
}

object OwnedArtifactInventoryCodec {
    fun encode(inventory: OwnedArtifactInventory): String = buildString {
        append("{\"schemaVersion\":1,\"ownedModules\":[")
        inventory.ownedModules.sorted().forEachIndexed { index, module ->
            if (index > 0) append(',')
            append(JsonOutput.toJson(module))
        }
        append("],\"ownedDescriptors\":[")
        inventory.ownedDescriptors.sorted().forEachIndexed { index, descriptor ->
            if (index > 0) append(',')
            append(JsonOutput.toJson(descriptor))
        }
        append("],\"ordinaryResources\":")
        appendResources(inventory.ordinaryOwnedResources)
        append(",\"hardenedResources\":")
        appendResources(inventory.hardenedOwnedResources)
        append("}\n")
    }

    fun decode(text: String): OwnedArtifactInventory {
        StrictJson.validateDocument(text)
        val root = JsonSlurper().parseText(text).inventoryMap("owned artifact inventory")
        root.requireKeys(ROOT_KEYS, "owned artifact inventory")
        require(root.inventoryInt("schemaVersion") == 1) { "unsupported owned artifact inventory schema" }
        val modules = root.inventoryStrings("ownedModules", "owned modules")
        val descriptors = root.inventoryStrings("ownedDescriptors", "owned descriptors")
        return OwnedArtifactInventory(
            ownedModules = modules.toCollection(linkedSetOf()).also {
                require(it.size == modules.size) { "owned modules must not contain duplicates" }
            },
            ownedDescriptors = descriptors.toCollection(linkedSetOf()).also {
                require(it.size == descriptors.size) { "owned descriptors must not contain duplicates" }
            },
            ordinaryOwnedResources = decodeResources(root["ordinaryResources"], "ordinary resources"),
            hardenedOwnedResources = decodeResources(root["hardenedResources"], "hardened resources"),
        )
    }

    private fun StringBuilder.appendResources(resources: Map<OwnedResourceKey, OwnedResourceLocation>) {
        append('[')
        resources.entries.sortedWith(compareBy<Map.Entry<OwnedResourceKey, OwnedResourceLocation>> { it.key.resourceId }
            .thenBy { it.key.qualifier }).forEachIndexed { index, (key, location) ->
            if (index > 0) append(',')
            append("{\"resourceId\":").append(key.resourceId)
            append(",\"qualifier\":").append(JsonOutput.toJson(key.qualifier))
            append(",\"entryName\":").append(JsonOutput.toJson(location.entryName))
            append(",\"aabPath\":").append(JsonOutput.toJson(location.aabPath))
            append(",\"apkPath\":").append(JsonOutput.toJson(location.apkPath))
            append(",\"semanticHash\":").append(JsonOutput.toJson(location.semanticHash)).append('}')
        }
        append(']')
    }

    private fun decodeResources(raw: Any?, label: String): Map<OwnedResourceKey, OwnedResourceLocation> {
        val items = raw as? List<*> ?: throw IllegalArgumentException("$label must be an array")
        val decoded = items.mapIndexed { index, item ->
            val value = item.inventoryMap("$label[$index]")
            value.requireKeys(RESOURCE_KEYS, "$label[$index]")
            OwnedResourceKey(value.inventoryInt("resourceId"), value.inventoryString("qualifier")) to
                OwnedResourceLocation(
                    entryName = value.inventoryString("entryName"),
                    aabPath = value.inventoryString("aabPath"),
                    apkPath = value.inventoryString("apkPath"),
                    semanticHash = value.inventoryString("semanticHash"),
                )
        }
        require(decoded.map(Pair<OwnedResourceKey, OwnedResourceLocation>::first).distinct().size == decoded.size) {
            "$label must not contain duplicate keys"
        }
        return decoded.toMap(linkedMapOf())
    }

    private fun Any?.inventoryMap(label: String): Map<*, *> =
        this as? Map<*, *> ?: throw IllegalArgumentException("$label must be an object")

    private fun Map<*, *>.requireKeys(expected: Set<String>, label: String) {
        require(keys == expected) { "$label keys must be exactly $expected" }
    }

    private fun Map<*, *>.inventoryString(key: String): String =
        this[key] as? String ?: throw IllegalArgumentException("$key must be a string")

    private fun Map<*, *>.inventoryStrings(key: String, label: String): List<String> =
        (this[key] as? List<*>)?.map { value ->
            value as? String ?: throw IllegalArgumentException("$label values must be strings")
        } ?: throw IllegalArgumentException("$label must be an array")

    private fun Map<*, *>.inventoryInt(key: String): Int {
        val number = this[key] as? Number ?: throw IllegalArgumentException("$key must be an integer")
        val value = number.toLong()
        require(number.toDouble() == value.toDouble() && value in Int.MIN_VALUE..Int.MAX_VALUE) {
            "$key must be a signed 32-bit integer"
        }
        return value.toInt()
    }

    private val ROOT_KEYS = setOf(
        "schemaVersion", "ownedModules", "ownedDescriptors", "ordinaryResources", "hardenedResources",
    )
    private val RESOURCE_KEYS = setOf("resourceId", "qualifier", "entryName", "aabPath", "apkPath", "semanticHash")
}
