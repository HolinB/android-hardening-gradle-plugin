package com.holin.android.hardening.resources

import com.android.aapt.Resources
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.instruction.FiveRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.instruction.RegisterRangeInstruction
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import com.android.tools.smali.dexlib2.iface.reference.StringReference
import com.google.protobuf.Message
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.nio.file.FileSystems
import java.nio.file.Path

data class ValueResourcePolicy(
    val enabled: Boolean = false,
    val includes: Set<String> = setOf("string/*", "color/*", "dimen/*"),
    val excludes: Set<String> = emptySet(),
    val minimumCoverage: Double = 0.0,
) {
    init {
        require(minimumCoverage.isFinite() && minimumCoverage in 0.0..1.0)
        require(includes.isNotEmpty())
        (includes + excludes).forEach { require(it.matches(Regex("(?:string|color|dimen)/[a-zA-Z0-9_*?]+"))) }
    }

    fun encode(): String = JsonOutput.toJson(mapOf("schemaVersion" to 1, "enabled" to enabled,
        "includes" to includes.sorted(), "excludes" to excludes.sorted(), "minimumCoverage" to minimumCoverage))

    fun select(inventory: List<ResourceInventoryEntry>, entries: Map<String, ByteArray>): ValueResourceDecision {
        val values = inventory.filter { it.type.isValue }.groupBy { it.resourceId }
        if (!enabled) return ValueResourceDecision(emptySet(), mapOf("enabled" to false, "entries" to emptyList<Any>()))
        val constants = mutableSetOf<String>()
        val dynamicTypes = mutableSetOf<String>()
        var nameObservations = false
        val dexPresent = entries.keys.any { it.endsWith(".dex") }
        entries.filterKeys { it.endsWith(".dex") }.values.forEach { bytes ->
            DexBackedDexFile.fromInputStream(Opcodes.getDefault(), bytes.inputStream()).classes.forEach { cls ->
                cls.methods.forEach methodLoop@ { method ->
                    val instructions = method.implementation?.instructions?.toList() ?: return@methodLoop
                    val branching = instructions.any { it is com.android.tools.smali.dexlib2.iface.instruction.OffsetInstruction } ||
                        method.implementation!!.tryBlocks.isNotEmpty()
                    instructions.forEachIndexed { index, instruction ->
                        val ref = (instruction as? ReferenceInstruction)?.reference
                        if (ref is StringReference) constants.add(ref.string)
                        if (ref !is MethodReference) return@forEachIndexed
                        if (ref.name in setOf("getResourceEntryName", "getResourceName")) nameObservations = true
                        if (ref.name != "getIdentifier" || ref.parameterTypes.map { it.toString() } != listOf("Ljava/lang/String;", "Ljava/lang/String;", "Ljava/lang/String;")) return@forEachIndexed
                        val typeRegister = when (instruction) {
                            is FiveRegisterInstruction -> instruction.registerE
                            is RegisterRangeInstruction -> instruction.startRegister + 2
                            else -> -1
                        }
                        val lastWrite = instructions.take(index).lastOrNull {
                            it.opcode.setsRegister() && it is OneRegisterInstruction && it.registerA == typeRegister
                        }
                        val type = if (branching) null else ((lastWrite as? ReferenceInstruction)?.reference as? StringReference)?.string
                        if (type in setOf("string", "color", "dimen")) dynamicTypes.add(type!!)
                        else if (type == null || type.isEmpty()) dynamicTypes.addAll(listOf("string", "color", "dimen"))
                    }
                }
            }
        }
        val unresolvedNames = mutableSetOf<String>()
        fun references(message: Message) {
            if (message is Resources.Reference && message.id == 0 && message.name.isNotEmpty()) unresolvedNames.add(message.name.substringAfter(':'))
            message.allFields.values.forEach { value ->
                if (value is Message) references(value)
                if (value is List<*>) value.filterIsInstance<Message>().forEach(::references)
            }
        }
        entries.filterKeys { it.endsWith("/resources.pb") }.values.forEach { references(Resources.ResourceTable.parseFrom(it)) }
        fun matches(patterns: Set<String>, key: String) = patterns.any {
            FileSystems.getDefault().getPathMatcher("glob:$it").matches(Path.of(key))
        }
        val eligible = mutableSetOf<Int>()
        var scoped = 0
        val records = values.toSortedMap().map { (id, variants) ->
            val entry = variants.first()
            val key = "${entry.type.directoryName}/${entry.name}"
            val included = matches(includes, key) && !matches(excludes, key)
            if (included) scoped++
            val reason = when {
                !included -> "OUTSIDE_CONFIGURED_SCOPE"
                !dexPresent -> "MISSING_BYTECODE_INVENTORY"
                entry.externallyNamed -> "EXTERNAL_NAME_CONTRACT"
                key in unresolvedNames -> "UNRESOLVED_SYMBOLIC_REFERENCE"
                entry.name in constants || key in constants -> "BYTECODE_NAME_LITERAL"
                nameObservations -> "RESOURCE_NAME_OBSERVATION_NOT_CLOSED"
                entry.type.directoryName in dynamicTypes -> "DYNAMIC_NAME_LOOKUP_NOT_CLOSED"
                else -> "LOGICAL_NAME_ONLY"
            }
            if (reason == "LOGICAL_NAME_ONLY") eligible.add(id)
            mapOf("resourceId" to id, "name" to key, "module" to entry.module,
                "variantCount" to variants.size, "eligible" to (id in eligible), "reason" to reason)
        }
        val coverage = if (scoped == 0) 0.0 else eligible.size.toDouble() / scoped
        require(coverage + 1e-12 >= minimumCoverage) { "value resource proven coverage $coverage is below $minimumCoverage" }
        return ValueResourceDecision(eligible, mapOf("schemaVersion" to 1, "enabled" to true,
            "discovered" to values.size, "scoped" to scoped, "eligible" to eligible.size,
            "plannedLogicalRenames" to eligible.size, "coverage" to coverage,
            "minimumCoverage" to minimumCoverage, "entries" to records))
    }

    companion object {
        fun decode(json: String): ValueResourcePolicy {
            com.holin.android.hardening.state.StrictJson.validateDocument(json)
            val values = JsonSlurper().parseText(json) as Map<*, *>
            require(values["schemaVersion"] == 1)
            return ValueResourcePolicy(values["enabled"] as Boolean,
                (values["includes"] as List<*>).map { it as String }.toSet(),
                (values["excludes"] as List<*>).map { it as String }.toSet(),
                (values["minimumCoverage"] as Number).toDouble())
        }
    }
}

data class ValueResourceDecision(val eligibleIds: Set<Int>, val report: Map<String, Any>)
