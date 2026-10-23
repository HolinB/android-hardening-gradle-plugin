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

data class RuntimeReaderCall(val owner: String, val method: String, val descriptor: String, val instruction: Int,
    val platform: String, val kind: String)

data class RuntimeBytecodeAnalysis(val stringNames: Set<String>, val assetsClosed: Boolean, val report: Map<String, Any>,
    val stringReport: Map<String, Any>, val calls: List<RuntimeReaderCall>, val policy: RuntimeProtectionPolicy) {
    fun requireStrings(reportPath: String = "") = RuntimeStringDiagnostics.requireCoverage(policy, stringNames, stringReport, reportPath)
    fun requireAssets() { require(assetsClosed || policy.minimumAssetCoverage == 0.0) { "asset reader closure failed: ${report["assetReasons"]}" } }
}

object RuntimeBytecodeAdapter {
    fun adapt(classes: Map<String, ByteArray>, hierarchy: Map<String, ByteArray>, ownedRoots: Set<String>, namespace: String,
        resourceXml: Map<String, String>, policy: RuntimeProtectionPolicy, helper: String): RuntimeAdaptation {
        val analysis = analyze(classes, hierarchy, ownedRoots, namespace, resourceXml, policy)
        analysis.requireStrings()
        analysis.requireAssets()
        return apply(classes, analysis, helper)
    }

    fun analyze(
        classes: Map<String, ByteArray>,
        hierarchy: Map<String, ByteArray>,
        ownedRoots: Set<String>,
        namespace: String,
        resourceXml: Map<String, String>,
        policy: RuntimeProtectionPolicy,
    ): RuntimeBytecodeAnalysis {
        val selected = policy.selectedStrings
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
        // AGP's scoped classes carry the current variant's R symbols, including when
        // javac/kotlinc has already inlined their final values in consumer classes.
        val symbolNode = hierarchy[rOwner]?.let { bytes ->
            ClassNode().also { ClassReader(bytes).accept(it, ClassReader.SKIP_CODE) }
        } ?: nodes[rOwner]
        val namesById = symbolNode?.fields.orEmpty().filter { it.name in selected && it.desc == "I" && it.value is Int }
            .groupBy { it.value as Int }.mapValues { (_, values) -> values.mapTo(linkedSetOf()) { it.name } }
        val unsafe = mutableMapOf<String, MutableSet<String>>()
        val candidates = mutableMapOf<MethodInsnNode, Pair<MutableSet<String>, String>>()
        val usedFields = linkedSetOf<FieldInsnNode>()
        val readers = linkedSetOf<MethodInsnNode>()
        val generalStrings = linkedMapOf<MethodInsnNode, String>()
        val textSetters = linkedMapOf<MethodInsnNode, String>()
        val sites = linkedMapOf<AbstractInsnNode, RuntimeReaderCall>()
        val locations = linkedMapOf<AbstractInsnNode, Map<String, Any>>()
        nodes.forEach { (owner, node) -> node.methods.forEach { method ->
            var line = -1
            method.instructions.forEachIndexed { index, instruction ->
                if (instruction is org.objectweb.asm.tree.LineNumberNode) line = instruction.line
                sites[instruction] = RuntimeReaderCall(owner, method.name, method.desc, index, "", "")
                locations[instruction] = mapOf("class" to owner, "method" to method.name, "descriptor" to method.desc,
                    "instruction" to index) + (if (line < 0) emptyMap() else mapOf("line" to line)) +
                    (node.sourceFile?.let { mapOf("sourceFile" to it) } ?: emptyMap())
            }
        } }
        val issues = linkedMapOf<String, MutableSet<RuntimeStringIssue>>()
        val stringReaders = linkedMapOf<String, MutableSet<Map<String, Any>>>()
        var currentInstruction: AbstractInsnNode? = null
        val dynamicNames = mutableMapOf<AbstractInsnNode, Set<String>>()
        val dynamicReturns = mutableMapOf<String, Set<String>>()
        val dynamicFields = mutableMapOf<String, Set<String>>()
        val dynamicArguments = mutableMapOf<String, MutableMap<Int, Set<String>>>()
        val returnParameters = mutableMapOf<String, Set<Int>>()
        val containerElements = linkedMapOf<AbstractInsnNode, Set<String>>()
        val containerAliases = linkedMapOf<AbstractInsnNode, Set<AbstractInsnNode>>()
        val containerFields = linkedMapOf<String, Set<AbstractInsnNode>>()
        val containerReturns = linkedMapOf<String, Set<AbstractInsnNode>>()
        val containerArguments = linkedMapOf<String, MutableMap<Int, Set<AbstractInsnNode>>>()
        val parameterMarkers = linkedMapOf<String, org.objectweb.asm.tree.LabelNode>()
        val relevantMethods = linkedSetOf<String>()
        val parameterDependencies = mutableMapOf<AbstractInsnNode, Set<Int>>()
        val programFields = nodes.flatMap { (owner, node) -> node.fields.map { "$owner#${it.name}:${it.desc}" } }.toSet()
        val programMethods = nodes.flatMap { (owner, node) -> node.methods.map { "$owner#${it.name}${it.desc}" to it } }.toMap()
        val implementations = programMethods.keys.groupBy { it.substringAfter('#') }
        val dispatchCache = mutableMapOf<String, List<String>>()
        fun subtype(owner: String, ancestor: String, seen: MutableSet<String> = hashSetOf()): Boolean {
            if (owner == ancestor) return true
            if (!seen.add(owner)) return false
            return listOfNotNull(parents[owner]).plus(nodes[owner]?.interfaces.orEmpty()).any { subtype(it, ancestor, seen) }
        }
        fun targets(call: MethodInsnNode): List<String> {
            val identity = "${call.opcode}:${call.owner}#${call.name}${call.desc}"
            return dispatchCache.getOrPut(identity) {
                val signature = "${call.name}${call.desc}"
                val declaring = generateSequence(call.owner) { parents[it] }.map { "$it#$signature" }
                    .firstOrNull { it in programMethods }
                val possible = if (call.opcode in setOf(Opcodes.INVOKESTATIC, Opcodes.INVOKESPECIAL)) listOfNotNull(declaring)
                    else listOfNotNull(declaring) + implementations[signature].orEmpty().filter { subtype(it.substringBefore('#'), call.owner) }
                possible.distinct().filter { programMethods.getValue(it).access and Opcodes.ACC_ABSTRACT == 0 }
            }
        }
        fun isContainerAllocation(instruction: AbstractInsnNode): Boolean = instruction.opcode == Opcodes.ANEWARRAY ||
            (instruction is org.objectweb.asm.tree.IntInsnNode && instruction.opcode == Opcodes.NEWARRAY && instruction.operand == Opcodes.T_INT) ||
            (instruction is org.objectweb.asm.tree.TypeInsnNode && instruction.opcode == Opcodes.NEW && instruction.desc == "java/util/ArrayList")
        // Empty factories and field initializers must establish identities before a caller
        // inserts a selected ID. Waiting for a tainted argument would miss these origins.
        if (selected.isNotEmpty()) nodes.forEach { (owner, node) -> node.methods.forEach { method ->
            if (method.instructions.any(::isContainerAllocation)) relevantMethods += "$owner#${method.name}${method.desc}"
        } }
        fun containers(value: SourceValue): Set<AbstractInsnNode> = value.insns.flatMapTo(linkedSetOf()) { instruction ->
            containerAliases[instruction].orEmpty() + when (instruction) {
                is FieldInsnNode -> containerFields["${instruction.owner}#${instruction.name}:${instruction.desc}"].orEmpty()
                is MethodInsnNode -> targets(instruction).flatMap { containerReturns[it].orEmpty() }
                else -> emptySet()
            } + if (instruction in containerElements || isContainerAllocation(instruction)) setOf(instruction) else emptySet()
        }
        fun summarySize() = dynamicReturns.values.sumOf { it.size } + dynamicFields.values.sumOf { it.size } +
            dynamicArguments.values.sumOf { slots -> slots.values.sumOf { it.size } } + returnParameters.values.sumOf { it.size } +
            containerElements.size + containerElements.values.sumOf { it.size } + containerFields.values.sumOf { it.size } +
            containerReturns.values.sumOf { it.size } + containerArguments.values.sumOf { slots -> slots.values.sumOf { it.size } } + relevantMethods.size +
            dynamicNames.values.sumOf { it.size } + containerAliases.values.sumOf { it.size }
        val readerMethods = linkedSetOf<String>()
        val assetReasons = linkedSetOf<String>()
        fun deny(names: Set<String>, reason: String) {
            val location = currentInstruction?.let { locations[it] }.orEmpty()
            val issue = RuntimeStringIssue(reason.substringBefore(':'), location, reason.substringAfter(':', ""))
            names.forEach { name ->
                unsafe.getOrPut(name) { linkedSetOf() }.add(reason)
                issues.getOrPut(name) { linkedSetOf() }.add(issue)
            }
        }
        val xmlIssues = RuntimeStringXmlReferences.scan(resourceXml, selected)
        fun restoreXmlIssues() = xmlIssues.forEach { (name, references) ->
            issues.getOrPut(name) { linkedSetOf() }.addAll(references)
            unsafe.getOrPut(name) { linkedSetOf() }.addAll(references.map { it.code })
        }
        fun fields(value: SourceValue): Set<FieldInsnNode> = value.insns.filterIsInstance<FieldInsnNode>()
            .filter { it.opcode == Opcodes.GETSTATIC && it.owner.endsWith("/R\$string") && it.name in selected }.toSet()
        fun literalNames(values: List<SourceValue>): Set<String> = values.flatMap { value ->
            fields(value).map { it.name } + value.insns.filterIsInstance<org.objectweb.asm.tree.LdcInsnNode>()
                .flatMap { namesById[it.cst].orEmpty() }
        }.toSet()
        fun dynamic(values: List<SourceValue>): Set<String> = values.flatMap { value -> containers(value).flatMap { containerElements[it].orEmpty() } + value.insns.flatMap { instruction ->
            dynamicNames[instruction].orEmpty() + when (instruction) {
                is MethodInsnNode -> if (instruction.name == "getIdentifier" && instruction.desc == "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I" &&
                    base(instruction.owner) == "android/content/res/Resources") emptySet()
                    else targets(instruction).flatMap { dynamicReturns[it].orEmpty() }
                is FieldInsnNode -> dynamicFields["${instruction.owner}#${instruction.name}:${instruction.desc}"].orEmpty()
                else -> emptySet()
            }
        } }.toSet()
        fun names(values: List<SourceValue>): Set<String> = literalNames(values) + dynamic(values)
        fun markFields(values: List<SourceValue>) { usedFields.addAll(values.flatMap(::fields)) }
        fun storeElements(roots: Set<AbstractInsnNode>, values: Set<String>) {
            if (roots.isEmpty()) deny(values, "UNRESOLVED_RESOURCE_ID_CONTAINER")
            roots.forEach { containerElements[it] = containerElements[it].orEmpty() + values }
        }
        fun modelContainer(call: MethodInsnNode, values: List<SourceValue>): Boolean {
            val signature = "${call.name}${call.desc}"
            val receiver = values.firstOrNull()?.let(::containers).orEmpty()
            fun fresh(contents: Set<String>) { storeElements(setOf(call), contents); containerAliases[call] = setOf(call) }
            fun alias(roots: Set<AbstractInsnNode>) { containerAliases[call] = containerAliases[call].orEmpty() + roots }
            if ((call.owner == "java/lang/Integer" && signature in setOf("valueOf(I)Ljava/lang/Integer;", "intValue()I")) ||
                (call.owner == "java/lang/Number" && signature == "intValue()I" && targets(call).isEmpty())) {
                dynamicNames[call] = dynamicNames[call].orEmpty() + names(values)
                markFields(values)
                return true
            }
            val kotlinLists = call.owner == "kotlin/collections/CollectionsKt" || call.owner.startsWith("kotlin/collections/CollectionsKt__")
            if ((call.owner == "java/util/Arrays" && signature == "asList([Ljava/lang/Object;)Ljava/util/List;") ||
                (kotlinLists && signature in setOf("listOf([Ljava/lang/Object;)Ljava/util/List;", "mutableListOf([Ljava/lang/Object;)Ljava/util/List;",
                    "arrayListOf([Ljava/lang/Object;)Ljava/util/ArrayList;", "listOf(Ljava/lang/Object;)Ljava/util/List;")) ||
                (call.owner == "java/util/Collections" && signature == "singletonList(Ljava/lang/Object;)Ljava/util/List;")) {
                if ((call.owner == "java/util/Arrays" || (kotlinLists && signature == "listOf([Ljava/lang/Object;)Ljava/util/List;")) && receiver.isNotEmpty()) alias(receiver) else fresh(names(values))
                markFields(values)
                return true
            }
            if (call.name == "clone" && call.desc == "()Ljava/lang/Object;" && (call.owner == "java/lang/Object" || call.owner.startsWith("[")) && receiver.isNotEmpty()) {
                fresh(names(values)); return true
            }
            if (call.owner == "java/util/Arrays" && signature in setOf("copyOf([II)[I", "copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;")) {
                deny(names(values.drop(1)), "RESOURCE_ID_USED_AS_CONTAINER_SIZE")
                fresh(names(values.take(1))); return true
            }
            if (call.owner == "java/lang/System" && signature == "arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V") {
                deny(names(listOf(values[1], values[3], values[4])), "RESOURCE_ID_USED_AS_CONTAINER_INDEX")
                storeElements(containers(values[2]), names(values.take(1))); return true
            }
            if (call.owner == "java/util/ArrayList" && call.name == "<init>" && call.desc in setOf("()V", "(I)V", "(Ljava/util/Collection;)V")) {
                if (call.desc == "(I)V") deny(names(values.drop(1)), "RESOURCE_ID_USED_AS_CONTAINER_SIZE")
                else storeElements(receiver, names(values.drop(1)))
                markFields(values); return true
            }
            if (call.owner in setOf("java/util/List", "java/util/ArrayList", "java/util/Collection", "java/lang/Iterable") && receiver.isNotEmpty()) {
                when (signature) {
                    "get(I)Ljava/lang/Object;" -> {
                        deny(names(values.drop(1)), "RESOURCE_ID_USED_AS_CONTAINER_INDEX")
                        dynamicNames[call] = dynamicNames[call].orEmpty() + names(values.take(1))
                    }
                    "add(Ljava/lang/Object;)Z", "add(ILjava/lang/Object;)V", "set(ILjava/lang/Object;)Ljava/lang/Object;" -> {
                        if (values.size == 3) deny(names(listOf(values[1])), "RESOURCE_ID_USED_AS_CONTAINER_INDEX")
                        if (call.name == "set") dynamicNames[call] = dynamicNames[call].orEmpty() + names(values.take(1))
                        storeElements(receiver, names(listOf(values.last())))
                    }
                    "iterator()Ljava/util/Iterator;" -> alias(receiver)
                    "size()I", "isEmpty()Z" -> Unit
                    else -> return false
                }
                markFields(values); return true
            }
            if (call.owner == "java/util/Iterator" && receiver.isNotEmpty()) {
                when (signature) {
                    "next()Ljava/lang/Object;" -> dynamicNames[call] = dynamicNames[call].orEmpty() + names(values)
                    "hasNext()Z" -> Unit
                    else -> return false
                }
                return true
            }
            return false
        }
        var previousSummarySize: Int
        var readersScanned = false
        do {
        previousSummarySize = summarySize()
        unsafe.clear()
        issues.clear()
        candidates.clear()
        usedFields.clear()
        stringReaders.clear()
        restoreXmlIssues()
        val dynamicSignatures = (dynamicReturns.keys + returnParameters.keys + containerReturns.keys + relevantMethods).mapTo(hashSetOf()) { it.substringAfter('#') }
        nodes.forEach { (owner, node) ->
            node.methods.forEach methodLoop@{ method ->
                val identity = "$owner#${method.name}${method.desc}"
                currentInstruction = null
                if (!readersScanned) method.instructions.filterIsInstance<MethodInsnNode>().forEach { call ->
                    val platform = base(call.owner)
                    if (call.opcode == Opcodes.INVOKEVIRTUAL && platform != null &&
                        ((call.name == "getString" && call.desc in setOf("(I)Ljava/lang/String;", "(I[Ljava/lang/Object;)Ljava/lang/String;")) ||
                        (call.name == "getText" && (call.desc == "(I)Ljava/lang/CharSequence;" ||
                            (platform == "android/content/res/Resources" && call.desc == "(ILjava/lang/CharSequence;)Ljava/lang/CharSequence;"))) ||
                        (platform == "android/content/res/Resources" && call.name == "getValue" && call.desc in setOf("(ILandroid/util/TypedValue;Z)V", "(Ljava/lang/String;Landroid/util/TypedValue;Z)V")) ||
                        (platform == "android/content/res/Resources" && call.name == "getValueForDensity" && call.desc == "(IILandroid/util/TypedValue;Z)V"))) {
                        generalStrings[call] = platform
                    }
                    if (policy.adaptTextViewResourceSetters && call.opcode in setOf(Opcodes.INVOKEVIRTUAL, Opcodes.INVOKESPECIAL) &&
                        call.name == "setText" && call.desc in setOf("(I)V", "(ILandroid/widget/TextView\$BufferType;)V") &&
                        subtype(call.owner, "android/widget/TextView")) {
                        val platformClass = hierarchy["android/widget/TextView"] ?: classes["android/widget/TextView"]
                        val platformNode = platformClass?.let { bytes -> ClassNode().also { ClassReader(bytes).accept(it, ClassReader.SKIP_CODE) } }
                        if (platformNode?.methods?.any { it.name == call.name && it.desc == call.desc && it.access and Opcodes.ACC_FINAL != 0 } == true) {
                            textSetters[call] = "android/widget/TextView"
                        }
                    }
                    if (call.owner == "android/content/res/AssetManager") {
                        if (call.opcode == Opcodes.INVOKEVIRTUAL && (
                            (call.name == "open" && call.desc in setOf("(Ljava/lang/String;)Ljava/io/InputStream;", "(Ljava/lang/String;I)Ljava/io/InputStream;")) ||
                            (call.name == "list" && call.desc == "(Ljava/lang/String;)[Ljava/lang/String;") ||
                            (call.name == "openFd" && call.desc == "(Ljava/lang/String;)Landroid/content/res/AssetFileDescriptor;"))) {
                            readers += call
                            if (owned(owner) && identity in policy.assetReaders && call.name == "open") readerMethods += identity
                        } else if (call.name in setOf("open", "openFd", "list", "openNonAsset", "openNonAssetFd")) {
                            assetReasons += "UNADAPTED_ASSET_READER:$identity"
                        }
                    }
                }
                if (method.instructions.size() == 0 || selected.isEmpty()) return@methodLoop
                val needsAnalysis = identity in relevantMethods || dynamicArguments[identity]?.isNotEmpty() == true || containerArguments[identity]?.isNotEmpty() == true || method.instructions.any { instruction ->
                    when (instruction) {
                        is org.objectweb.asm.tree.LdcInsnNode -> instruction.cst in namesById
                        is FieldInsnNode -> (instruction.owner.endsWith("/R\$string") && instruction.name in selected) ||
                            ("${instruction.owner}#${instruction.name}:${instruction.desc}" in dynamicFields ||
                                "${instruction.owner}#${instruction.name}:${instruction.desc}" in containerFields)
                        is MethodInsnNode -> instruction.name == "getIdentifier" ||
                            "${instruction.name}${instruction.desc}" in dynamicSignatures
                        else -> false
                    }
                }
                if (!needsAnalysis) return@methodLoop
                relevantMethods += identity
                val interpreter = object : SourceInterpreter(Opcodes.ASM9) {
                    override fun newParameterValue(isInstanceMethod: Boolean, local: Int, type: org.objectweb.asm.Type): SourceValue {
                        val selected = dynamicArguments[identity]?.get(local).orEmpty()
                        val roots = containerArguments[identity]?.get(local).orEmpty()
                        if (selected.isEmpty() && roots.isEmpty()) return super.newParameterValue(isInstanceMethod, local, type)
                        val marker = parameterMarkers.getOrPut("$identity:$local") { org.objectweb.asm.tree.LabelNode() }
                        dynamicNames[marker] = selected
                        containerAliases[marker] = roots
                        parameterDependencies[marker] = setOf(local)
                        return SourceValue(type.size, marker)
                    }
                    override fun copyOperation(insn: AbstractInsnNode, value: SourceValue): SourceValue = value
                    override fun unaryOperation(insn: AbstractInsnNode, value: SourceValue): SourceValue? {
                        currentInstruction = insn
                        if (insn.opcode !in setOf(Opcodes.IFNULL, Opcodes.IFNONNULL, Opcodes.IFEQ, Opcodes.IFNE, Opcodes.IFLT, Opcodes.IFGE, Opcodes.IFGT, Opcodes.IFLE,
                                Opcodes.TABLESWITCH, Opcodes.LOOKUPSWITCH)) {
                            val lookup = names(listOf(value))
                            when {
                                insn.opcode in setOf(Opcodes.IRETURN, Opcodes.ARETURN, Opcodes.ARRAYLENGTH) -> markFields(listOf(value))
                                insn.opcode == Opcodes.CHECKCAST -> {
                                    dynamicNames[insn] = lookup
                                    containerAliases[insn] = containers(value)
                                    parameterDependencies[insn] = value.insns.flatMapTo(linkedSetOf()) { parameterDependencies[it].orEmpty() }
                                    markFields(listOf(value))
                                }
                                insn.opcode == Opcodes.PUTSTATIC && insn is FieldInsnNode -> {
                                    val field = "${insn.owner}#${insn.name}:${insn.desc}"
                                    if (field !in programFields) deny(lookup, "EXTERNAL_RESOURCE_ID_FIELD")
                                    if (lookup.isNotEmpty()) dynamicFields[field] = dynamicFields[field].orEmpty() + lookup
                                    val roots = containers(value)
                                    if (roots.isNotEmpty()) containerFields[field] = containerFields[field].orEmpty() + roots
                                    markFields(listOf(value))
                                }
                                else -> deny(lookup, "RESOURCE_ID_ESCAPES_CLOSED_GETSTRING")
                            }
                        }
                        return super.unaryOperation(insn, value)
                    }
                    override fun binaryOperation(insn: AbstractInsnNode, first: SourceValue, second: SourceValue): SourceValue? {
                        currentInstruction = insn
                        if (insn.opcode !in Opcodes.IF_ICMPEQ..Opcodes.IF_ICMPLE) {
                            val lookup = names(listOf(first, second))
                            if (insn.opcode in setOf(Opcodes.IALOAD, Opcodes.AALOAD)) {
                                deny(names(listOf(second)), "RESOURCE_ID_USED_AS_CONTAINER_INDEX")
                                dynamicNames[insn] = names(listOf(first))
                                parameterDependencies[insn] = first.insns.flatMapTo(linkedSetOf()) { parameterDependencies[it].orEmpty() }
                            } else if (insn.opcode == Opcodes.PUTFIELD && insn is FieldInsnNode) {
                                val field = "${insn.owner}#${insn.name}:${insn.desc}"
                                if (field !in programFields) deny(lookup, "EXTERNAL_RESOURCE_ID_FIELD")
                                    if (lookup.isNotEmpty()) dynamicFields[field] = dynamicFields[field].orEmpty() + lookup
                                val roots = containers(second)
                                if (roots.isNotEmpty()) containerFields[field] = containerFields[field].orEmpty() + roots
                                markFields(listOf(second))
                            } else deny(lookup, "RESOURCE_ID_ESCAPES_CLOSED_GETSTRING")
                        }
                        return super.binaryOperation(insn, first, second)
                    }
                    override fun ternaryOperation(insn: AbstractInsnNode, a: SourceValue, b: SourceValue, c: SourceValue): SourceValue? {
                        currentInstruction = insn
                        if (insn.opcode in setOf(Opcodes.IASTORE, Opcodes.AASTORE)) {
                            deny(names(listOf(b)), "RESOURCE_ID_USED_AS_CONTAINER_INDEX")
                            storeElements(containers(a), names(listOf(c)))
                            markFields(listOf(c))
                        } else deny(names(listOf(a, b, c)), "RESOURCE_ID_ESCAPES_CLOSED_GETSTRING")
                        return super.ternaryOperation(insn, a, b, c)
                    }
                    override fun returnOperation(insn: AbstractInsnNode, value: SourceValue, expected: SourceValue) {
                        currentInstruction = insn
                        markFields(listOf(value))
                        val roots = containers(value)
                        if (roots.isNotEmpty()) containerReturns[identity] = containerReturns[identity].orEmpty() + roots
                        val parameters = value.insns.flatMapTo(linkedSetOf()) { parameterDependencies[it].orEmpty() }
                        if (parameters.isNotEmpty()) returnParameters[identity] = returnParameters[identity].orEmpty() + parameters
                        val independent = names(value.insns.filter { parameterDependencies[it].isNullOrEmpty() }.map { SourceValue(value.size, it) })
                        if (independent.isNotEmpty()) {
                            dynamicReturns[identity] = dynamicReturns[identity].orEmpty() + independent
                        }
                        super.returnOperation(insn, value, expected)
                    }
                    override fun naryOperation(insn: AbstractInsnNode, values: MutableList<out SourceValue>): SourceValue? {
                        currentInstruction = insn
                        val invocation = insn as? MethodInsnNode
                        if (invocation != null && modelContainer(invocation, values)) return super.naryOperation(insn, values)
                        invocation?.let { call ->
                            val targetSlots = targets(call).flatMapTo(linkedSetOf()) { returnParameters[it].orEmpty() }
                            var slot = 0
                            val returned = values.filter { value ->
                                val included = slot in targetSlots
                                slot += value.size
                                included
                            }
                            if (returned.isNotEmpty()) {
                                dynamicNames[call] = names(returned)
                                containerAliases[call] = returned.flatMapTo(linkedSetOf(), ::containers)
                                parameterDependencies[call] = returned.flatMapTo(linkedSetOf()) { value -> value.insns.flatMap { parameterDependencies[it].orEmpty() } }
                            }
                        }
                        if (invocation?.name == "getIdentifier" && invocation.desc == "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I" &&
                            base(invocation.owner) == "android/content/res/Resources") {
                            fun constant(index: Int): String? = values.getOrNull(index)?.insns?.singleOrNull()
                                ?.let { (it as? org.objectweb.asm.tree.LdcInsnNode)?.cst as? String }
                            val name = constant(1)
                            val type = constant(2)
                            val selected = when {
                                type != null && type != "string" && type.isNotEmpty() -> emptySet()
                                name != null -> selected.filterTo(linkedSetOf()) { it == name.substringAfterLast('/').substringAfterLast(':') }
                                else -> selected
                            }
                            dynamicNames[insn] = dynamicNames[insn].orEmpty() + selected
                        }
                        val referenced = names(values)
                        if (referenced.isNotEmpty() || values.any { containers(it).isNotEmpty() }) {
                            val call = insn as? MethodInsnNode
                            val idValue = values.getOrNull(1)
                            val idSources = idValue?.let(::fields).orEmpty()
                            val idNames = idValue?.let { names(listOf(it)) }.orEmpty()
                            val platform = call?.let { textSetters[it] ?: base(it.owner) }
                            if (call != null && (call in generalStrings || call in textSetters) && platform != null &&
                                idNames.isNotEmpty() && idSources.all { it.owner == rOwner } &&
                                values.filterIndexed { index, _ -> index != 1 }.all { names(listOf(it)).isEmpty() }) {
                                usedFields += idSources
                                idNames.forEach { name ->
                                    candidates.getOrPut(call) { linkedSetOf<String>() to platform }.first.add(name)
                                    stringReaders.getOrPut(name) { linkedSetOf() }.add(locations.getValue(call) +
                                        mapOf("consumer" to "${call.owner}#${call.name}${call.desc}", "adapter" to if (call in textSetters) "TEXT_VIEW_RESOURCE_SETTER" else "PLATFORM_GETTER"))
                                }
                            } else {
                                val destinations = call?.let(::targets).orEmpty()
                                val transferable = destinations.isNotEmpty() && destinations.all { programMethods.getValue(it).access and Opcodes.ACC_NATIVE == 0 }
                                val typedDrawableReader = call != null && call.owner in setOf("androidx/core/content/ContextCompat",
                                    "androidx/core/content/res/ResourcesCompat", "androidx/appcompat/content/res/AppCompatResources",
                                    "com/bumptech/glide/load/resource/drawable/DrawableDecoderCompat") && call.name == "getDrawable" &&
                                    call.desc.endsWith(")Landroid/graphics/drawable/Drawable;")
                                val idOnly = values.filter { names(listOf(it)).isNotEmpty() }.all { containers(it).isEmpty() } && literalNames(values).isEmpty() && call != null && (typedDrawableReader ||
                                    (platform == "android/content/Context" && call.name in setOf("getDrawable", "getColor", "getColorStateList")) ||
                                    (platform == "android/content/res/Resources" && call.name in setOf("getXml", "getDrawable", "getDrawableForDensity", "getColor", "getColorStateList",
                                        "getBoolean", "getInteger", "getDimension", "getDimensionPixelSize", "getDimensionPixelOffset", "getResourceName", "getResourceEntryName",
                                        "getResourceTypeName", "getResourcePackageName", "openRawResource", "openRawResourceFd", "getStringArray", "getTextArray")) ||
                                    (call.owner in setOf("java/lang/StringBuilder", "java/lang/StringBuffer") && call.name == "append" && call.desc.startsWith("(I)")) ||
                                    (call.owner == "java/lang/String" && call.name == "valueOf" && call.desc == "(I)Ljava/lang/String;") ||
                                    (call.owner == "android/os/Parcel" && call.name == "writeInt") ||
                                    (call.owner in setOf("android/os/Bundle", "android/os/PersistableBundle") && call.name == "putInt") ||
                                    (call.owner == "java/lang/Integer" && call.name in setOf("valueOf", "intValue", "toHexString")) ||
                                    (call.owner == "java/io/DataOutputStream" && call.name == "writeInt" && call.desc == "(I)V") ||
                                    (call.owner == "java/io/PrintWriter" && call.name in setOf("print", "println") && call.desc == "(I)V") ||
                                    (call.owner == "java/lang/System" && call.name == "arraycopy") ||
                                    (call.owner.startsWith("android/view/accessibility/") && call.name == "setSource" && call.desc == "(Landroid/view/View;I)V") ||
                                    (call.owner == "android/graphics/BitmapFactory" && call.name in setOf("decodeByteArray", "decodeResource")) ||
                                    (call.owner == "android/graphics/drawable/Icon" && call.name in setOf("createWithResource", "createWithData")) ||
                                    (call.owner == "android/content/Intent\$ShortcutIconResource" && call.name == "fromContext") ||
                                    (call.owner == "android/widget/RemoteViews" && call.name == "setImageViewResource") ||
                                    (call.owner == "android/app/Notification\$Builder" && call.name in setOf("addAction", "setSmallIcon")) ||
                                    (call.owner == "android/app/Notification\$Action\$Builder" && call.name == "<init>"))
                                if (transferable && !idOnly) {
                                    destinations.forEach { target ->
                                        var local = 0
                                        values.forEach { value ->
                                            val selected = names(listOf(value))
                                            if (selected.isNotEmpty()) {
                                                val slots = dynamicArguments.getOrPut(target) { mutableMapOf() }
                                                slots[local] = slots[local].orEmpty() + selected
                                            }
                                            val roots = containers(value)
                                            if (roots.isNotEmpty()) {
                                                val slots = containerArguments.getOrPut(target) { mutableMapOf() }
                                                slots[local] = slots[local].orEmpty() + roots
                                            }
                                            local += value.size
                                        }
                                    }
                                    usedFields.addAll(values.flatMap(::fields))
                                }
                                if (!idOnly && !transferable) deny(referenced, "NON_PLATFORM_OR_UNPROVEN_GETSTRING_READER:${call?.owner}#${call?.name}${call?.desc}")
                            }
                        }
                        return super.naryOperation(insn, values)
                    }
                }
                Analyzer(interpreter).analyze(owner, method)
                method.instructions.filterIsInstance<FieldInsnNode>().filter {
                    it.owner.endsWith("/R\$string") && it.name in selected
                }.filterNot { it in usedFields }.forEach { currentInstruction = it; deny(setOf(it.name), "UNADAPTED_RESOURCE_ID_REFERENCE") }
            }
        }
        readersScanned = true
        } while (previousSummarySize != summarySize())
        // Third-party callers do not receive the adapter. Any dynamic lookup or selected ID reference blocks protection.
        hierarchy.filterKeys { it !in classes && !it.startsWith("android/") && !it.startsWith("java/") }.forEach { (owner, bytes) ->
            val node = ClassNode()
            ClassReader(bytes).accept(node, ClassReader.SKIP_FRAMES)
            node.methods.forEach { method ->
                var line = -1
                method.instructions.forEachIndexed { index, insn ->
                if (insn is org.objectweb.asm.tree.LineNumberNode) line = insn.line
                locations[insn] = mapOf("class" to owner, "method" to method.name, "descriptor" to method.desc,
                    "instruction" to index) + (if (line < 0) emptyMap() else mapOf("line" to line)) +
                    (node.sourceFile?.let { mapOf("sourceFile" to it) } ?: emptyMap())
                currentInstruction = insn
                if (insn is FieldInsnNode && insn.owner.endsWith("/R\$string") && insn.name in selected) {
                    deny(setOf(insn.name), "EXTERNAL_RESOURCE_READER:$owner")
                }
                if (insn is org.objectweb.asm.tree.LdcInsnNode && insn.cst is Int) {
                    deny(namesById[insn.cst].orEmpty(), "EXTERNAL_INLINED_RESOURCE_READER:$owner")
                }
                if (insn is MethodInsnNode && insn.name == "getIdentifier" && insn.desc == "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I") {
                    deny(selected, "EXTERNAL_DYNAMIC_RESOURCE_LOOKUP:$owner")
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
        currentInstruction = null
        if (symbolNode != null) deny(selected - symbolNode.fields.mapTo(hashSetOf()) { it.name }, "RESOURCE_NOT_IN_SYMBOLS")
        val proven = candidates.values.flatMapTo(linkedSetOf()) { it.first } - unsafe.keys
        val missing = selected - candidates.values.flatMap { it.first }.toSet()
        currentInstruction = null
        deny(missing, "NO_TRACEABLE_PLATFORM_GETSTRING")
        if (readerMethods != policy.assetReaders) assetReasons += "MISSING_OR_UNSUPPORTED_CONFIGURED_READER"
        val assetsClosed = policy.assetPaths.isNotEmpty() && assetReasons.isEmpty() && readers.isNotEmpty()
        val calls = mutableListOf<RuntimeReaderCall>()
        if (proven.isNotEmpty()) {
            generalStrings.forEach { (call, platform) ->
                val kind = when (call.name) {
                    "getText" -> "text"
                    "getValue" -> "value"
                    "getValueForDensity" -> "valueForDensity"
                    else -> if (call.desc.startsWith("(I[")) "format" else "string"
                }
                val site = sites.getValue(call)
                calls += RuntimeReaderCall(site.owner, site.method, site.descriptor, site.instruction, platform, kind)
            }
            textSetters.forEach { (call, platform) ->
                val site = sites.getValue(call)
                calls += RuntimeReaderCall(site.owner, site.method, site.descriptor, site.instruction, platform, "setText")
            }
        }
        if (assetsClosed) readers.forEach { call ->
            val site = sites.getValue(call)
            calls += RuntimeReaderCall(site.owner, site.method, site.descriptor, site.instruction, "android/content/res/AssetManager", call.name)
        }
        val stringReport = RuntimeStringDiagnostics.report(policy, proven, null, issues, stringReaders, namespace)
        val report = mapOf("schemaVersion" to 1, "stage" to "READERS", "status" to stringReport.getValue("status"), "stringSelected" to selected.size, "stringClosed" to proven.size,
            "stringCoverage" to if (selected.isEmpty()) 0.0 else proven.size.toDouble() / selected.size,
            "strings" to selected.sorted().map { mapOf("name" to it, "closed" to (it in proven), "reasons" to unsafe[it].orEmpty().sorted()) },
            "stringAnalysis" to stringReport, "assetReaders" to readerMethods.sorted(), "assetsClosed" to assetsClosed,
            "assetReasons" to assetReasons.sorted(), "adaptedCallCount" to calls.size,
            "textViewMetadataDifference" to calls.any { it.kind == "setText" })
        return RuntimeBytecodeAnalysis(proven, assetsClosed, report, stringReport, calls, policy)
    }

    fun apply(classes: Map<String, ByteArray>, analysis: RuntimeBytecodeAnalysis, helper: String): RuntimeAdaptation {
        val callsByClass = analysis.calls.groupBy { it.owner }
        val output = classes.mapValues { (owner, original) ->
            val calls = callsByClass[owner] ?: return@mapValues original
            val node = ClassNode().also { ClassReader(original).accept(it, 0) }
            val rewritten = linkedMapOf<MethodInsnNode, List<Any>>()
            calls.forEach { site ->
                val method = node.methods.single { it.name == site.method && it.desc == site.descriptor }
                val call = method.instructions[site.instruction] as MethodInsnNode
                rewritten[call] = listOf(call.opcode, call.owner, call.name, call.desc, call.itf)
                call.opcode = Opcodes.INVOKESTATIC
                call.owner = helper
                call.name = site.kind
                call.desc = "(L${site.platform};" + call.desc.substring(1)
                call.itf = false
            }
            val changed = ClassWriter(0).also(node::accept).toByteArray()
            rewritten.forEach { (call, before) ->
                call.opcode = before[0] as Int; call.owner = before[1] as String; call.name = before[2] as String
                call.desc = before[3] as String; call.itf = before[4] as Boolean
            }
            val restored = ClassWriter(0).also(node::accept).toByteArray()
            val normalized = ClassWriter(0).also { ClassReader(original).accept(it, 0) }.toByteArray()
            require(restored.contentEquals(normalized)) { "runtime reader inverse bytecode proof failed: $owner" }
            changed
        }
        return RuntimeAdaptation(output, analysis.stringNames, analysis.assetsClosed, analysis.report + mapOf("inverseBytecodeProof" to true))
    }
}
