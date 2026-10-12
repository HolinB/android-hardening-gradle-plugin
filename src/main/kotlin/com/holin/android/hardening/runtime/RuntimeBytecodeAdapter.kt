package com.holin.android.hardening.runtime

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.analysis.Analyzer
import org.objectweb.asm.tree.analysis.SourceInterpreter
import org.objectweb.asm.tree.analysis.SourceValue

data class RuntimeAdaptation(
    val classes: Map<String, ByteArray>,
    val stringNames: Set<String>,
    val assetsClosed: Boolean,
    val report: Map<String, Any>,
)

object RuntimeBytecodeAdapter {
    fun adapt(
        classes: Map<String, ByteArray>,
        hierarchy: Map<String, ByteArray>,
        ownedRoots: Set<String>,
        namespace: String,
        resourceXml: Map<String, String>,
        policy: RuntimeProtectionPolicy,
        helper: String,
    ): RuntimeAdaptation {
        val nodes = classes.mapValues { (_, bytes) -> ClassNode().also { ClassReader(bytes).accept(it, 0) } }
        val parents = (hierarchy + classes).mapValues { (_, bytes) -> ClassReader(bytes).superName }
        fun base(owner: String): String? {
            var current: String? = owner
            val seen = hashSetOf<String>()
            while (current != null && seen.add(current)) {
                if (current in setOf("android/content/Context", "android/content/res/Resources")) return current
                current = parents[current]
            }
            return null
        }
        fun owned(owner: String) = ownedRoots.any { owner == it || owner.startsWith(it + '$') }
        val rOwner = namespace.replace('.', '/') + "/R\$string"
        val unsafe = mutableMapOf<String, MutableSet<String>>()
        val candidates = mutableMapOf<MethodInsnNode, Pair<String, String>>()
        val usedFields = linkedSetOf<FieldInsnNode>()
        val readers = mutableListOf<MethodInsnNode>()
        val readerMethods = linkedSetOf<String>()
        val assetReasons = linkedSetOf<String>()
        fun deny(names: Set<String>, reason: String) { names.forEach { unsafe.getOrPut(it) { linkedSetOf() }.add(reason) } }
        policy.strings.forEach { name ->
            if (resourceXml.values.any { Regex("@(?:[A-Za-z0-9_.]+:)?string/" + Regex.escape(name) + "\\b").containsMatchIn(it) }) {
                deny(setOf(name), "XML_OR_RESOURCE_ALIAS_REFERENCE")
            }
        }
        fun fields(value: SourceValue): Set<FieldInsnNode> = value.insns.filterIsInstance<FieldInsnNode>()
            .filter { it.opcode == Opcodes.GETSTATIC && it.owner.endsWith("/R\$string") && it.name in policy.strings }.toSet()
        fun names(values: List<SourceValue>): Set<String> = values.flatMap { fields(it).map { field -> field.name } }.toSet()
        nodes.forEach { (owner, node) ->
            node.methods.forEach methodLoop@{ method ->
                val identity = "$owner#${method.name}${method.desc}"
                method.instructions.filterIsInstance<MethodInsnNode>().forEach { call ->
                    if (call.name == "getIdentifier" && call.desc == "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I") {
                        deny(policy.strings, "DYNAMIC_RESOURCE_LOOKUP")
                    }
                    if (call.owner == "android/content/res/AssetManager") {
                        if (owned(owner) && identity in policy.assetReaders && call.name == "open" && call.desc == "(Ljava/lang/String;)Ljava/io/InputStream;") {
                            readers += call
                            readerMethods += identity
                        } else if (call.name in setOf("open", "openFd", "list", "openNonAsset", "openNonAssetFd")) {
                            assetReasons += "UNADAPTED_OWNED_OR_GENERATED_ASSET_READER:$identity"
                        }
                    }
                }
                if (method.instructions.size() == 0 || policy.strings.isEmpty()) return@methodLoop
                val interpreter = object : SourceInterpreter(Opcodes.ASM9) {
                    override fun copyOperation(insn: AbstractInsnNode, value: SourceValue): SourceValue = value
                    override fun unaryOperation(insn: AbstractInsnNode, value: SourceValue): SourceValue? {
                        deny(names(listOf(value)), "RESOURCE_ID_ESCAPES_CLOSED_GETSTRING")
                        return super.unaryOperation(insn, value)
                    }
                    override fun binaryOperation(insn: AbstractInsnNode, first: SourceValue, second: SourceValue): SourceValue? {
                        deny(names(listOf(first, second)), "RESOURCE_ID_ESCAPES_CLOSED_GETSTRING")
                        return super.binaryOperation(insn, first, second)
                    }
                    override fun ternaryOperation(insn: AbstractInsnNode, a: SourceValue, b: SourceValue, c: SourceValue): SourceValue? {
                        deny(names(listOf(a, b, c)), "RESOURCE_ID_ESCAPES_CLOSED_GETSTRING")
                        return super.ternaryOperation(insn, a, b, c)
                    }
                    override fun returnOperation(insn: AbstractInsnNode, value: SourceValue, expected: SourceValue) {
                        deny(names(listOf(value)), "RESOURCE_ID_ESCAPES_CLOSED_GETSTRING")
                        super.returnOperation(insn, value, expected)
                    }
                    override fun naryOperation(insn: AbstractInsnNode, values: MutableList<out SourceValue>): SourceValue? {
                        val referenced = names(values)
                        if (referenced.isNotEmpty()) {
                            val call = insn as? MethodInsnNode
                            val idSources = values.getOrNull(1)?.let(::fields).orEmpty()
                            val platform = call?.let { base(it.owner) }
                            if (owned(owner) && call != null && call.opcode == Opcodes.INVOKEVIRTUAL && platform != null &&
                                call.name == "getString" && call.desc in setOf("(I)Ljava/lang/String;", "(I[Ljava/lang/Object;)Ljava/lang/String;") &&
                                idSources.size == 1 && idSources.single().owner == rOwner && referenced.size == 1 &&
                                values.filterIndexed { index, _ -> index != 1 }.all { fields(it).isEmpty() }) {
                                usedFields += idSources
                                candidates[call] = idSources.single().name to platform
                            } else deny(referenced, "NON_PLATFORM_OR_UNPROVEN_GETSTRING_READER")
                        }
                        return super.naryOperation(insn, values)
                    }
                }
                Analyzer(interpreter).analyze(owner, method)
                method.instructions.filterIsInstance<FieldInsnNode>().filter {
                    it.owner.endsWith("/R\$string") && it.name in policy.strings
                }.filterNot { it in usedFields }.forEach { deny(setOf(it.name), "UNADAPTED_RESOURCE_ID_REFERENCE") }
            }
        }
        // Third-party callers do not receive the adapter. Any dynamic lookup or selected ID reference blocks protection.
        hierarchy.filterKeys { it !in classes && !it.startsWith("android/") && !it.startsWith("java/") }.forEach { (owner, bytes) ->
            val node = ClassNode()
            ClassReader(bytes).accept(node, ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
            node.methods.forEach { method -> method.instructions.forEach { insn ->
                if (insn is FieldInsnNode && insn.owner.endsWith("/R\$string") && insn.name in policy.strings) {
                    deny(setOf(insn.name), "EXTERNAL_RESOURCE_READER:$owner")
                }
                if (insn is MethodInsnNode && insn.name == "getIdentifier" && insn.desc == "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I") {
                    deny(policy.strings, "EXTERNAL_DYNAMIC_RESOURCE_LOOKUP:$owner")
                }
                if (insn is MethodInsnNode && insn.owner == "android/content/res/AssetManager" && insn.name in setOf("open", "openFd", "list")) {
                    // Only constant external paths outside the selected paths/prefixes are closed in v1.
                    var previous = insn.previous
                    while (previous != null && previous.opcode < 0) previous = previous.previous
                    val path = (previous as? org.objectweb.asm.tree.LdcInsnNode)?.cst as? String
                    if (path == null || policy.assetPaths.any { selected -> selected == path || (insn.name == "list" && selected.startsWith(path.trimEnd('/') + "/")) || (insn.name == "list" && path.isEmpty()) }) {
                        assetReasons += "EXTERNAL_DYNAMIC_ASSET_READER:$owner"
                    }
                }
            } }
        }
        val proven = candidates.values.mapTo(linkedSetOf()) { it.first } - unsafe.keys
        val missing = policy.strings - candidates.values.map { it.first }.toSet()
        deny(missing, "NO_TRACEABLE_PLATFORM_GETSTRING")
        val stringCoverage = if (policy.strings.isEmpty()) 0.0 else proven.size.toDouble() / policy.strings.size
        require(stringCoverage >= policy.minimumStringCoverage) { "closed getString coverage $stringCoverage is below ${policy.minimumStringCoverage}: $unsafe" }
        if (readerMethods != policy.assetReaders) assetReasons += "MISSING_OR_UNSUPPORTED_CONFIGURED_READER"
        val assetsClosed = policy.assetPaths.isNotEmpty() && assetReasons.isEmpty() && readers.isNotEmpty()
        require(assetsClosed || policy.minimumAssetCoverage == 0.0) { "asset reader closure failed: $assetReasons" }
        val rewrittenCalls = linkedMapOf<MethodInsnNode, List<Any>>()
        candidates.filterValues { it.first in proven }.forEach { (call, value) ->
            rewrittenCalls[call] = listOf(call.opcode, call.owner, call.name, call.desc, call.itf)
            val platform = value.second
            call.opcode = Opcodes.INVOKESTATIC
            call.owner = helper
            call.name = if (call.desc.startsWith("(I[")) "format" else "string"
            call.desc = "(L$platform;" + call.desc.substring(1)
            call.itf = false
        }
        if (assetsClosed) readers.forEach { call ->
            rewrittenCalls[call] = listOf(call.opcode, call.owner, call.name, call.desc, call.itf)
            call.opcode = Opcodes.INVOKESTATIC
            call.owner = helper
            call.desc = "(Landroid/content/res/AssetManager;Ljava/lang/String;)Ljava/io/InputStream;"
            call.itf = false
        }
        val output = nodes.mapValues { (name, node) ->
            val writer = ClassWriter(0)
            node.accept(writer)
            val changed = writer.toByteArray()
            // Inverse only the declared calls, independently of the data-flow selection.
            node.methods.forEach { method -> method.instructions.filterIsInstance<MethodInsnNode>().forEach { call ->
                rewrittenCalls[call]?.let { original ->
                    call.opcode = original[0] as Int; call.owner = original[1] as String; call.name = original[2] as String
                    call.desc = original[3] as String; call.itf = original[4] as Boolean
                }
            } }
            val restored = ClassWriter(0).also(node::accept).toByteArray()
            val normalized = ClassWriter(0).also { ClassReader(classes.getValue(name)).accept(it, 0) }.toByteArray()
            require(restored.contentEquals(normalized)) { "runtime reader inverse bytecode proof failed: $name" }
            if (changed.contentEquals(restored)) classes.getValue(name) else changed
        }
        return RuntimeAdaptation(output, proven, assetsClosed, mapOf("schemaVersion" to 1,
            "stringSelected" to policy.strings.size, "stringClosed" to proven.size, "stringCoverage" to stringCoverage,
            "strings" to policy.strings.sorted().map { mapOf("name" to it, "closed" to (it in proven), "reasons" to unsafe[it].orEmpty().sorted()) },
            "assetReaders" to readerMethods.sorted(), "assetsClosed" to assetsClosed, "assetReasons" to assetReasons.sorted(),
            "adaptedCallCount" to rewrittenCalls.size, "inverseBytecodeProof" to true))
    }
}
