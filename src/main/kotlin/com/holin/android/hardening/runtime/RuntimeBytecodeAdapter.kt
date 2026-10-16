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
        // AGP's scoped classes carry the current variant's R symbols, including when
        // javac/kotlinc has already inlined their final values in consumer classes.
        val symbolNode = nodes[rOwner] ?: hierarchy[rOwner]?.let { bytes ->
            ClassNode().also { ClassReader(bytes).accept(it, ClassReader.SKIP_CODE) }
        }
        val namesById = symbolNode?.fields.orEmpty().filter { it.name in policy.strings && it.desc == "I" && it.value is Int }
            .groupBy { it.value as Int }.mapValues { (_, values) -> values.mapTo(linkedSetOf()) { it.name } }
        val unsafe = mutableMapOf<String, MutableSet<String>>()
        val candidates = mutableMapOf<MethodInsnNode, Pair<MutableSet<String>, String>>()
        val usedFields = linkedSetOf<FieldInsnNode>()
        val readers = linkedSetOf<MethodInsnNode>()
        val generalStrings = linkedMapOf<MethodInsnNode, String>()
        val dynamicNames = mutableMapOf<AbstractInsnNode, Set<String>>()
        val dynamicReturns = mutableMapOf<String, Set<String>>()
        val dynamicFields = mutableMapOf<String, Set<String>>()
        val dynamicArguments = mutableMapOf<String, MutableMap<Int, Set<String>>>()
        val returnParameters = mutableMapOf<String, Set<Int>>()
        val parameterDependencies = mutableMapOf<AbstractInsnNode, Set<Int>>()
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
                possible.distinct().filter { programMethods.getValue(it).access and (Opcodes.ACC_NATIVE or Opcodes.ACC_ABSTRACT) == 0 }
            }
        }
        fun summarySize() = dynamicReturns.values.sumOf { it.size } + dynamicFields.values.sumOf { it.size } +
            dynamicArguments.values.sumOf { slots -> slots.values.sumOf { it.size } } + returnParameters.values.sumOf { it.size }
        val readerMethods = linkedSetOf<String>()
        val assetReasons = linkedSetOf<String>()
        var currentReader = "resource-xml"
        fun deny(names: Set<String>, reason: String) { names.forEach { unsafe.getOrPut(it) { linkedSetOf() }.add("$reason:$currentReader") } }
        policy.strings.forEach { name ->
            if (resourceXml.values.any { Regex("@(?:[A-Za-z0-9_.]+:)?string/" + Regex.escape(name) + "\\b").containsMatchIn(it) }) {
                deny(setOf(name), "XML_OR_RESOURCE_ALIAS_REFERENCE")
            }
        }
        fun fields(value: SourceValue): Set<FieldInsnNode> = value.insns.filterIsInstance<FieldInsnNode>()
            .filter { it.opcode == Opcodes.GETSTATIC && it.owner.endsWith("/R\$string") && it.name in policy.strings }.toSet()
        fun literalNames(values: List<SourceValue>): Set<String> = values.flatMap { value ->
            fields(value).map { it.name } + value.insns.filterIsInstance<org.objectweb.asm.tree.LdcInsnNode>()
                .flatMap { namesById[it.cst].orEmpty() }
        }.toSet()
        fun dynamic(values: List<SourceValue>): Set<String> = values.flatMap { value -> value.insns.flatMap { instruction ->
            dynamicNames[instruction].orEmpty() + when (instruction) {
                is MethodInsnNode -> if (instruction.name == "getIdentifier" && instruction.desc == "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I" &&
                    base(instruction.owner) == "android/content/res/Resources") emptySet()
                    else targets(instruction).flatMap { dynamicReturns[it].orEmpty() }
                is FieldInsnNode -> dynamicFields["${instruction.owner}#${instruction.name}:${instruction.desc}"].orEmpty()
                else -> emptySet()
            }
        } }.toSet()
        fun names(values: List<SourceValue>): Set<String> = literalNames(values) + dynamic(values)
        var previousSummarySize: Int
        var readersScanned = false
        do {
        previousSummarySize = summarySize()
        val dynamicSignatures = (dynamicReturns.keys + returnParameters.keys).mapTo(hashSetOf()) { it.substringAfter('#') }
        nodes.forEach { (owner, node) ->
            node.methods.forEach methodLoop@{ method ->
                val identity = "$owner#${method.name}${method.desc}"
                currentReader = identity
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
                if (method.instructions.size() == 0 || policy.strings.isEmpty()) return@methodLoop
                val needsAnalysis = dynamicArguments[identity]?.isNotEmpty() == true || method.instructions.any { instruction ->
                    when (instruction) {
                        is org.objectweb.asm.tree.LdcInsnNode -> instruction.cst in namesById
                        is FieldInsnNode -> (instruction.owner.endsWith("/R\$string") && instruction.name in policy.strings) ||
                            "${instruction.owner}#${instruction.name}:${instruction.desc}" in dynamicFields
                        is MethodInsnNode -> instruction.name == "getIdentifier" ||
                            "${instruction.name}${instruction.desc}" in dynamicSignatures
                        else -> false
                    }
                }
                if (!needsAnalysis) return@methodLoop
                val interpreter = object : SourceInterpreter(Opcodes.ASM9) {
                    override fun newParameterValue(isInstanceMethod: Boolean, local: Int, type: org.objectweb.asm.Type): SourceValue {
                        val selected = dynamicArguments[identity]?.get(local).orEmpty()
                        if (selected.isEmpty()) return super.newParameterValue(isInstanceMethod, local, type)
                        val marker = org.objectweb.asm.tree.LabelNode()
                        dynamicNames[marker] = selected
                        parameterDependencies[marker] = setOf(local)
                        return SourceValue(type.size, marker)
                    }
                    override fun copyOperation(insn: AbstractInsnNode, value: SourceValue): SourceValue = value
                    override fun unaryOperation(insn: AbstractInsnNode, value: SourceValue): SourceValue? {
                        if (insn.opcode !in setOf(Opcodes.IFNULL, Opcodes.IFNONNULL, Opcodes.IFEQ, Opcodes.IFNE, Opcodes.IFLT, Opcodes.IFGE, Opcodes.IFGT, Opcodes.IFLE,
                                Opcodes.TABLESWITCH, Opcodes.LOOKUPSWITCH)) {
                            val constant = literalNames(listOf(value))
                            deny(constant, "RESOURCE_ID_ESCAPES_CLOSED_GETSTRING")
                            val lookup = dynamic(listOf(value))
                            when {
                                insn.opcode in setOf(Opcodes.IRETURN, Opcodes.ARETURN, Opcodes.ARRAYLENGTH) -> Unit
                                insn.opcode == Opcodes.CHECKCAST -> {
                                    dynamicNames[insn] = lookup
                                    parameterDependencies[insn] = value.insns.flatMapTo(linkedSetOf()) { parameterDependencies[it].orEmpty() }
                                }
                                insn.opcode == Opcodes.PUTSTATIC && insn is FieldInsnNode -> {
                                    val field = "${insn.owner}#${insn.name}:${insn.desc}"
                                    if (lookup.isNotEmpty()) dynamicFields[field] = dynamicFields[field].orEmpty() + lookup
                                }
                                else -> deny(lookup, "DYNAMIC_RESOURCE_ID_ESCAPES")
                            }
                        }
                        return super.unaryOperation(insn, value)
                    }
                    override fun binaryOperation(insn: AbstractInsnNode, first: SourceValue, second: SourceValue): SourceValue? {
                        if (insn.opcode !in Opcodes.IF_ICMPEQ..Opcodes.IF_ICMPLE) {
                            deny(literalNames(listOf(first, second)), "RESOURCE_ID_ESCAPES_CLOSED_GETSTRING")
                            val lookup = dynamic(listOf(first, second))
                            if (insn.opcode == Opcodes.IALOAD) {
                                dynamicNames[insn] = dynamic(listOf(first))
                                parameterDependencies[insn] = first.insns.flatMapTo(linkedSetOf()) { parameterDependencies[it].orEmpty() }
                            } else if (insn.opcode == Opcodes.PUTFIELD && insn is FieldInsnNode) {
                                val field = "${insn.owner}#${insn.name}:${insn.desc}"
                                if (lookup.isNotEmpty()) dynamicFields[field] = dynamicFields[field].orEmpty() + lookup
                            } else deny(lookup, "DYNAMIC_RESOURCE_ID_ESCAPES")
                        }
                        return super.binaryOperation(insn, first, second)
                    }
                    override fun ternaryOperation(insn: AbstractInsnNode, a: SourceValue, b: SourceValue, c: SourceValue): SourceValue? {
                        if (insn.opcode == Opcodes.IASTORE) {
                            val lookup = names(listOf(c))
                            val arrays = a.insns.filterIsInstance<FieldInsnNode>()
                            arrays.forEach { field ->
                                val arrayIdentity = "${field.owner}#${field.name}:${field.desc}"
                                if (lookup.isNotEmpty()) dynamicFields[arrayIdentity] = dynamicFields[arrayIdentity].orEmpty() + lookup
                            }
                            if (arrays.isEmpty()) deny(lookup, "UNRESOLVED_RESOURCE_ID_ARRAY")
                        } else deny(names(listOf(a, b, c)), "RESOURCE_ID_ESCAPES_CLOSED_GETSTRING")
                        return super.ternaryOperation(insn, a, b, c)
                    }
                    override fun returnOperation(insn: AbstractInsnNode, value: SourceValue, expected: SourceValue) {
                        deny(literalNames(listOf(value)), "RESOURCE_ID_ESCAPES_CLOSED_GETSTRING")
                        val parameters = value.insns.flatMapTo(linkedSetOf()) { parameterDependencies[it].orEmpty() }
                        if (parameters.isNotEmpty()) returnParameters[identity] = returnParameters[identity].orEmpty() + parameters
                        val independent = dynamic(value.insns.filter { parameterDependencies[it].isNullOrEmpty() }.map { SourceValue(value.size, it) })
                        if (independent.isNotEmpty()) {
                            dynamicReturns[identity] = dynamicReturns[identity].orEmpty() + independent
                        }
                        super.returnOperation(insn, value, expected)
                    }
                    override fun naryOperation(insn: AbstractInsnNode, values: MutableList<out SourceValue>): SourceValue? {
                        val invocation = insn as? MethodInsnNode
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
                                name != null -> policy.strings.filterTo(linkedSetOf()) { it == name.substringAfterLast('/').substringAfterLast(':') }
                                else -> policy.strings
                            }
                            dynamicNames[insn] = dynamicNames[insn].orEmpty() + selected
                        }
                        val referenced = names(values)
                        if (referenced.isNotEmpty()) {
                            val call = insn as? MethodInsnNode
                            val idValue = values.getOrNull(1)
                            val idSources = idValue?.let(::fields).orEmpty()
                            val idNames = idValue?.let { names(listOf(it)) }.orEmpty()
                            val platform = call?.let { base(it.owner) }
                            if (call != null && call in generalStrings && platform != null &&
                                idNames.isNotEmpty() && idSources.all { it.owner == rOwner } &&
                                values.filterIndexed { index, _ -> index != 1 }.all { names(listOf(it)).isEmpty() }) {
                                usedFields += idSources
                                idNames.forEach { selected -> candidates.getOrPut(call) { linkedSetOf<String>() to platform }.first.add(selected) }
                            } else {
                                val destinations = call?.let(::targets).orEmpty()
                                val transferable = destinations.isNotEmpty()
                                val passThrough = call != null && (
                                    (call.owner == "java/util/Arrays" && call.name == "copyOf" && call.desc == "([II)[I") ||
                                    (call.owner == "java/lang/Object" && call.name == "clone" && call.desc == "()Ljava/lang/Object;"))
                                if (passThrough) {
                                    dynamicNames[insn] = names(values)
                                    parameterDependencies[insn] = values.flatMapTo(linkedSetOf()) { value -> value.insns.flatMap { parameterDependencies[it].orEmpty() } }
                                }
                                val typedDrawableReader = call != null && call.owner in setOf("androidx/core/content/ContextCompat",
                                    "androidx/core/content/res/ResourcesCompat", "androidx/appcompat/content/res/AppCompatResources",
                                    "com/bumptech/glide/load/resource/drawable/DrawableDecoderCompat") && call.name == "getDrawable" &&
                                    call.desc.endsWith(")Landroid/graphics/drawable/Drawable;")
                                val idOnly = literalNames(values).isEmpty() && call != null && (typedDrawableReader ||
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
                                if (transferable && !idOnly && !passThrough) {
                                    destinations.forEach { target ->
                                        var local = 0
                                        values.forEach { value ->
                                            val selected = names(listOf(value))
                                            if (selected.isNotEmpty()) {
                                                val slots = dynamicArguments.getOrPut(target) { mutableMapOf() }
                                                slots[local] = slots[local].orEmpty() + selected
                                            }
                                            local += value.size
                                        }
                                    }
                                    usedFields.addAll(values.flatMap(::fields))
                                }
                                if (!idOnly && !transferable && !passThrough) deny(referenced, "NON_PLATFORM_OR_UNPROVEN_GETSTRING_READER:${call?.owner}#${call?.name}${call?.desc}")
                            }
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
        readersScanned = true
        } while (previousSummarySize != summarySize())
        // Third-party callers do not receive the adapter. Any dynamic lookup or selected ID reference blocks protection.
        hierarchy.filterKeys { it !in classes && !it.startsWith("android/") && !it.startsWith("java/") }.forEach { (owner, bytes) ->
            val node = ClassNode()
            ClassReader(bytes).accept(node, ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
            node.methods.forEach { method -> method.instructions.forEach { insn ->
                if (insn is FieldInsnNode && insn.owner.endsWith("/R\$string") && insn.name in policy.strings) {
                    deny(setOf(insn.name), "EXTERNAL_RESOURCE_READER:$owner")
                }
                if (insn is org.objectweb.asm.tree.LdcInsnNode && insn.cst is Int) {
                    deny(namesById[insn.cst].orEmpty(), "EXTERNAL_INLINED_RESOURCE_READER:$owner")
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
        val proven = candidates.values.flatMapTo(linkedSetOf()) { it.first } - unsafe.keys
        val missing = policy.strings - candidates.values.flatMap { it.first }.toSet()
        deny(missing, "NO_TRACEABLE_PLATFORM_GETSTRING")
        val stringCoverage = if (policy.strings.isEmpty()) 0.0 else proven.size.toDouble() / policy.strings.size
        require(stringCoverage >= policy.minimumStringCoverage) { "closed getString coverage $stringCoverage is below ${policy.minimumStringCoverage}: $unsafe" }
        if (readerMethods != policy.assetReaders) assetReasons += "MISSING_OR_UNSUPPORTED_CONFIGURED_READER"
        val assetsClosed = policy.assetPaths.isNotEmpty() && assetReasons.isEmpty() && readers.isNotEmpty()
        require(assetsClosed || policy.minimumAssetCoverage == 0.0) { "asset reader closure failed: $assetReasons" }
        val rewrittenCalls = linkedMapOf<MethodInsnNode, List<Any>>()
        if (proven.isNotEmpty()) generalStrings.forEach { (call, platform) ->
            rewrittenCalls[call] = listOf(call.opcode, call.owner, call.name, call.desc, call.itf)
            call.opcode = Opcodes.INVOKESTATIC
            call.owner = helper
            call.name = when (call.name) {
                "getText" -> "text"
                "getValue" -> "value"
                "getValueForDensity" -> "valueForDensity"
                else -> if (call.desc.startsWith("(I[")) "format" else "string"
            }
            call.desc = "(L$platform;" + call.desc.substring(1)
            call.itf = false
        }
        if (assetsClosed) readers.forEach { call ->
            rewrittenCalls[call] = listOf(call.opcode, call.owner, call.name, call.desc, call.itf)
            call.opcode = Opcodes.INVOKESTATIC
            call.owner = helper
            call.desc = "(Landroid/content/res/AssetManager;" + call.desc.substring(1)
            call.itf = false
        }
        val output = nodes.mapValues { (name, node) ->
            if (node.methods.none { method -> method.instructions.any { it in rewrittenCalls } }) return@mapValues classes.getValue(name)
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
