package com.holin.android.hardening.runtime

import com.holin.android.hardening.state.Sha256
import com.holin.android.hardening.state.StrictJson
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class RuntimeProtectionPolicy(
    val strings: Set<String> = emptySet(),
    val minimumStringCoverage: Double = 0.0,
    val assetPaths: Set<String> = emptySet(),
    val assetReaders: Set<String> = emptySet(),
    val minimumAssetCoverage: Double = 0.0,
    val images: RuntimeImagePolicy = RuntimeImagePolicy(),
    val requiredStrings: Set<String> = emptySet(),
    val candidateStrings: Set<String> = emptySet(),
    val excludedStrings: Map<String, String> = emptyMap(),
    val adaptTextViewResourceSetters: Boolean = false,
) {
    init {
        require(minimumStringCoverage.isFinite() && minimumStringCoverage in 0.0..1.0)
        require(minimumAssetCoverage.isFinite() && minimumAssetCoverage in 0.0..1.0)
        val groups = listOf(strings, requiredStrings, candidateStrings, excludedStrings.keys)
        groups.flatten().forEach { require(Regex("[a-z][a-z0-9_]*").matches(it)) { "invalid runtime string name: $it" } }
        val conflicts = groups.flatten().groupingBy { it }.eachCount().filterValues { it > 1 }.keys.sorted()
        require(conflicts.isEmpty()) { "runtime string groups overlap: $conflicts" }
        require(excludedStrings.values.all { it.isNotBlank() }) { "excluded runtime strings require a nonblank reason" }
        assetPaths.forEach { require(it.isNotBlank() && !it.startsWith('/') && '\\' !in it && it.split('/').none { part -> part in setOf(".", "..", "") }) }
        assetReaders.forEach { require('#' in it && '(' in it && ')' in it) { "assetReaders use internal/Class#method(descriptor)" } }
        require(assetPaths.isEmpty() || assetReaders.isNotEmpty()) { "asset containers require explicit owned reader methods" }
    }
    val selectedStrings: Set<String> get() = strings + requiredStrings + candidateStrings
    val declaredStrings: Set<String> get() = selectedStrings + excludedStrings.keys
    val hasStringGroups: Boolean get() = requiredStrings.isNotEmpty() || candidateStrings.isNotEmpty() || excludedStrings.isNotEmpty()
    val extended: Boolean get() = hasStringGroups || adaptTextViewResourceSetters
    val enabled: Boolean get() = declaredStrings.isNotEmpty() || assetPaths.isNotEmpty() || images.enabled
    fun encode(): String = JsonOutput.toJson(mapOf("schemaVersion" to if (extended) 2 else 1, "strings" to strings.sorted(),
        "minimumStringCoverage" to minimumStringCoverage, "assetPaths" to assetPaths.sorted(),
        "assetReaders" to assetReaders.sorted(), "minimumAssetCoverage" to minimumAssetCoverage) +
        (if (images.enabled) mapOf("images" to images.values()) else emptyMap()) +
        (if (extended) mapOf("requiredStrings" to requiredStrings.sorted(), "candidateStrings" to candidateStrings.sorted(),
            "excludedStrings" to excludedStrings.toSortedMap(), "adaptTextViewResourceSetters" to adaptTextViewResourceSetters) else emptyMap()))
    companion object {
        fun decode(text: String): RuntimeProtectionPolicy {
            StrictJson.validateDocument(text)
            val p = JsonSlurper().parseText(text) as Map<*, *>
            require(p["schemaVersion"] in setOf(1, 2)) { "unsupported runtime policy schema" }
            fun names(key: String) = (p[key] as List<*>).map { it as String }.toSet()
            return RuntimeProtectionPolicy(names("strings"), (p["minimumStringCoverage"] as Number).toDouble(),
                names("assetPaths"), names("assetReaders"), (p["minimumAssetCoverage"] as Number).toDouble(),
                (p["images"] as? Map<*, *>)?.let(RuntimeImagePolicy::read) ?: RuntimeImagePolicy(),
                if (p["schemaVersion"] == 2) names("requiredStrings") else emptySet(),
                if (p["schemaVersion"] == 2) names("candidateStrings") else emptySet(),
                if (p["schemaVersion"] == 2) (p["excludedStrings"] as Map<*, *>).entries.associate { it.key as String to it.value as String } else emptyMap(),
                if (p["schemaVersion"] == 2) p["adaptTextViewResourceSetters"] as Boolean else false)
        }
    }
}

object RuntimeEnvelope {
    private val marker = byteArrayOf(72, 82, 68, 49)
    fun key(seed: ByteArray): ByteArray = java.security.MessageDigest.getInstance("SHA-256")
        .digest(seed + "hardening-runtime-v1".toByteArray())
    fun helper(seed: ByteArray): String = "h" + Sha256.hex(seed + "runtime-class-v1".toByteArray()).take(20) + "/Bridge"
    fun prefix(key: ByteArray): String = "h1_" + Sha256.hex(key).take(24) + ":"
    fun pathKey(path: String, key: ByteArray): String = Sha256.hex(key + path.toByteArray(Charsets.UTF_8))
    fun assetPath(path: String, key: ByteArray): String = path.substringBeforeLast('/', "").let { directory ->
        (if (directory.isEmpty()) "" else "$directory/") + "_h_" + pathKey(path, key) + ".bin"
    }

    fun encrypt(bytes: ByteArray, key: ByteArray, identity: String): ByteArray {
        val nonce = java.security.MessageDigest.getInstance("SHA-256").digest(key + identity.toByteArray() + bytes).copyOf(12)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(marker)
        return marker + nonce + cipher.doFinal(bytes)
    }
    fun decrypt(bytes: ByteArray, key: ByteArray): ByteArray {
        require(bytes.size >= 32 && bytes.copyOfRange(0, 4).contentEquals(marker)) { "invalid runtime envelope" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, bytes.copyOfRange(4, 16)))
        cipher.updateAAD(marker)
        return cipher.doFinal(bytes.copyOfRange(16, bytes.size))
    }
    fun encodeString(text: String, key: ByteArray, identity: String): String = prefix(key) +
        Base64.getEncoder().encodeToString(encrypt(text.toByteArray(Charsets.UTF_8), key, identity))
    fun decodeString(text: String, key: ByteArray): String {
        require(text.startsWith(prefix(key))) { "resource string is not a proven runtime envelope" }
        return String(decrypt(Base64.getDecoder().decode(text.substring(prefix(key).length)), key), Charsets.UTF_8)
    }
}

data class RuntimeStringScope(val names: Set<String>, val key: ByteArray, val minimumCoverage: Double, val requestedCount: Int = names.size)

data class RuntimeStringPlan(val table: ByteArray, val ids: Set<Int>, val report: Map<String, Any>)

data class RuntimeStringResourceAnalysis(val names: Set<String>, val report: Map<String, Any>)

object RuntimeStringResources {
    private fun plain(entry: com.android.aapt.Resources.Entry): Boolean = entry.configValueCount > 0 && entry.configValueList.all {
        it.value.hasItem() && it.value.item.hasStr() &&
            !it.value.item.str.value.startsWith("res/") && !it.value.item.str.value.startsWith("assets/") &&
            !Regex("(?i).*\\.(png|webp|jpe?g|xml)").matches(it.value.item.str.value)
    }

    private fun references(table: com.android.aapt.Resources.ResourceTable, entries: Map<String, ByteArray>): Map<Int, Set<String>> {
        val referenced = linkedMapOf<Int, MutableSet<String>>()
        fun visit(message: com.google.protobuf.Message, path: String) {
            if (message is com.android.aapt.Resources.Reference && message.id != 0) referenced.getOrPut(message.id) { linkedSetOf() }.add(path)
            message.allFields.values.forEach { value ->
                when (value) {
                    is com.google.protobuf.Message -> visit(value, path)
                    is List<*> -> value.filterIsInstance<com.google.protobuf.Message>().forEach { visit(it, path) }
                }
            }
        }
        visit(table, "base/resources.pb")
        entries.filterKeys { it.endsWith(".xml") }.toSortedMap().forEach { (path, xml) ->
            runCatching { com.android.aapt.Resources.XmlNode.parseFrom(xml) }.getOrNull()?.let { visit(it, path) }
        }
        return referenced
    }

    fun analyze(bytes: ByteArray, policy: RuntimeProtectionPolicy, closed: Set<String>, owned: Set<String>,
        namespace: String, entries: Map<String, ByteArray>, readerAnalysis: Map<String, Any> = emptyMap()): RuntimeStringResourceAnalysis {
        val table = com.android.aapt.Resources.ResourceTable.parseFrom(bytes)
        val referenced = references(table, entries)
        val found = linkedMapOf<String, MutableList<Pair<Int, com.android.aapt.Resources.Entry>>>()
        table.packageList.forEach { pkg -> pkg.typeList.filter { it.name == "string" }.forEach { type -> type.entryList.forEach { entry ->
            if (entry.name in policy.selectedStrings) {
                val id = (pkg.packageId.id shl 24) or (type.typeId.id shl 16) or entry.entryId.id
                found.getOrPut(entry.name) { mutableListOf() }.add(id to entry)
            }
        } } }
        val reasons = linkedMapOf<String, List<RuntimeStringIssue>>()
        val eligible = linkedSetOf<String>()
        policy.selectedStrings.sorted().forEach { name ->
            val matches = found[name].orEmpty()
            val rejected = mutableListOf<RuntimeStringIssue>()
            if (matches.isEmpty()) rejected += RuntimeStringIssue("ABSENT_AFTER_R8")
            if (matches.size > 1) rejected += RuntimeStringIssue("AMBIGUOUS_RESOURCE_ID")
            if (name !in closed) rejected += RuntimeStringIssue("READERS_NOT_CLOSED")
            if (name !in owned) rejected += RuntimeStringIssue("NOT_OWNED")
            matches.forEach { (id, entry) ->
                referenced[id].orEmpty().sorted().forEach { path -> rejected += RuntimeStringIssue("COMPILED_XML_OR_RESOURCE_REFERENCE",
                    mapOf("file" to path, "resourceId" to id.toUInt().toString(16))) }
                if (!plain(entry)) rejected += RuntimeStringIssue("ALIASED_RICH_OR_UNSUPPORTED_VALUE", mapOf("resourceId" to id.toUInt().toString(16)))
            }
            if (rejected.isEmpty()) eligible += name else reasons[name] = rejected
        }
        val baseReport = RuntimeStringDiagnostics.report(policy, closed, null, reasons, emptyMap(), namespace, "FINAL", eligible)
        val readerRows = (readerAnalysis["entries"] as? List<*>)?.filterIsInstance<Map<*, *>>()?.associateBy { it["name"] }.orEmpty()
        @Suppress("UNCHECKED_CAST")
        val rows = (baseReport["entries"] as List<Map<String, Any>>).map { row ->
            val prior = readerRows[row["name"]]
            row + mapOf("readers" to (prior?.get("readers") ?: emptyList<Any>()),
                "reasons" to ((row["reasons"] as List<*>) + (prior?.get("reasons") as? List<*> ?: emptyList<Any>())).distinct())
        }
        val report = baseReport + mapOf("entries" to rows) +
            mapOf("resourceTableSha256" to Sha256.hex(bytes))
        return RuntimeStringResourceAnalysis(eligible, report)
    }

    fun transform(bytes: ByteArray, scope: RuntimeStringScope, salt: ByteArray, entries: Map<String, ByteArray> = emptyMap()): RuntimeStringPlan {
        val table = com.android.aapt.Resources.ResourceTable.parseFrom(bytes)
        val referenced = references(table, entries)
        val builder = table.toBuilder()
        val ids = linkedSetOf<Int>()
        val rows = mutableListOf<Map<String, Any>>()
        val seen = linkedSetOf<String>()
        table.packageList.forEachIndexed { pi, pkg -> pkg.typeList.forEachIndexed typeLoop@{ ti, type ->
            if (type.name != "string") return@typeLoop
            type.entryList.forEachIndexed entryLoop@{ ei, entry ->
                if (entry.name !in scope.names) return@entryLoop
                seen += entry.name
                val id = (pkg.packageId.id shl 24) or (type.typeId.id shl 16) or entry.entryId.id
                val eligible = id !in referenced && plain(entry)
                if (eligible) {
                    entry.configValueList.forEachIndexed { ci, value ->
                        val encrypted = RuntimeEnvelope.encodeString(value.value.item.str.value, scope.key,
                            "string:$id:${Sha256.hex(value.config.toByteArray())}:${Sha256.hex(salt)}")
                        builder.getPackageBuilder(pi).getTypeBuilder(ti).getEntryBuilder(ei).getConfigValueBuilder(ci)
                            .valueBuilder.itemBuilder.strBuilder.value = encrypted
                    }
                    ids += id
                }
                rows += mapOf("name" to entry.name, "id" to id.toUInt().toString(16), "configurations" to entry.configValueCount,
                    "reason" to if (eligible) "PLAIN_STRING_ALL_CONFIGURATIONS" else if (id in referenced) "COMPILED_XML_OR_RESOURCE_REFERENCE" else "ALIASED_RICH_OR_UNSUPPORTED_VALUE", "transformed" to eligible)
            }
        } }
        (scope.names - seen).sorted().forEach { rows += mapOf("name" to it, "transformed" to false, "reason" to "ABSENT_AFTER_R8") }
        val coverage = if (scope.requestedCount == 0) 0.0 else ids.size.toDouble() / scope.requestedCount
        require(coverage >= scope.minimumCoverage) { "runtime string coverage $coverage is below ${scope.minimumCoverage}" }
        val output = builder.build().toByteArray()
        val restored = normalize(output, ids, scope.key)
        require(restored.contentEquals(bytes)) { "runtime string independent table proof failed" }
        return RuntimeStringPlan(output, ids, mapOf("schemaVersion" to 1, "selected" to scope.requestedCount, "closedReaders" to scope.names.size,
            "transformed" to ids.size, "coverage" to coverage, "entries" to rows))
    }

    /** Decrypt precisely the expected resource IDs; all qualifiers and other protobuf fields remain intact. */
    fun normalize(bytes: ByteArray, ids: Set<Int>, key: ByteArray): ByteArray {
        if (ids.isEmpty()) return bytes
        val table = com.android.aapt.Resources.ResourceTable.parseFrom(bytes)
        val builder = table.toBuilder()
        val seen = linkedSetOf<Int>()
        table.packageList.forEachIndexed { pi, pkg -> pkg.typeList.forEachIndexed { ti, type -> type.entryList.forEachIndexed { ei, entry ->
            val id = (pkg.packageId.id shl 24) or (type.typeId.id shl 16) or entry.entryId.id
            if (id in ids) {
                require(type.name == "string" && entry.configValueCount > 0)
                seen += id
                entry.configValueList.forEachIndexed { ci, config ->
                    require(config.value.hasItem() && config.value.item.hasStr())
                    builder.getPackageBuilder(pi).getTypeBuilder(ti).getEntryBuilder(ei).getConfigValueBuilder(ci)
                        .valueBuilder.itemBuilder.strBuilder.value = RuntimeEnvelope.decodeString(config.value.item.str.value, key)
                }
            }
        } } }
        require(seen == ids) { "runtime string ID set changed" }
        return builder.build().toByteArray()
    }
}
