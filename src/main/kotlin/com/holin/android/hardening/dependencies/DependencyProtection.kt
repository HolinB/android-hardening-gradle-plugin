package com.holin.android.hardening.dependencies

import com.holin.android.hardening.components.PreR8Relocation
import com.holin.android.hardening.state.Sha256
import com.holin.android.hardening.state.StrictJson
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.*

data class DependencyPolicy(
    val enabled: Boolean = false,
    val includes: Set<String> = emptySet(),
    val excludes: Set<String> = emptySet(),
    val minimumCoverage: Double = 0.0,
) {
    init {
        require(minimumCoverage.isFinite() && minimumCoverage in 0.0..1.0)
        (includes + excludes).forEach { require(Regex("[^:\\s]+:[^:\\s]+:[^:\\s]+").matches(it)) }
    }
    fun encode() = JsonOutput.toJson(mapOf("schemaVersion" to 1, "enabled" to enabled, "includes" to includes.sorted(),
        "excludes" to excludes.sorted(), "minimumCoverage" to minimumCoverage))
    companion object {
        fun decode(text: String): DependencyPolicy {
            StrictJson.validateDocument(text)
            val p = JsonSlurper().parseText(text) as Map<*, *>
            require(p["schemaVersion"] == 1)
            return DependencyPolicy(p["enabled"] as Boolean, (p["includes"] as List<*>).map { it as String }.toSet(),
                (p["excludes"] as List<*>).map { it as String }.toSet(), (p["minimumCoverage"] as Number).toDouble())
        }
    }
}

data class DependencyCandidate(val coordinate: String, val originalEntries: Map<String, ByteArray>, val classes: Map<String, ByteArray>, val plainJar: Boolean)
data class DependencyPlan(val aliases: Map<String, String>, val entries: Map<String, ByteArray>, val report: Map<String, Any>)

/** Deliberately narrow proof: stateless Java utility classes with only closed invokestatic references. */
object DependencyProtection {
    fun plan(classes: Map<String, ByteArray>, artifacts: List<DependencyCandidate>, policy: DependencyPolicy, seed: ByteArray): DependencyPlan {
        val aliases = linkedMapOf<String, String>()
        val nodes = classes.mapValues { read(it.value) }
        val reflection = nodes.values.any { n -> n.methods.any { m -> m.instructions.any { i ->
            i is MethodInsnNode && ((i.owner == "java/lang/Class" && i.name in setOf("forName", "getName", "getSimpleName", "getCanonicalName")) ||
                (i.name in setOf("loadClass", "findClass", "defineClass")) || i.owner.startsWith("java/lang/reflect/"))
        } } }
        val rows = artifacts.sortedBy { it.coordinate }.map { artifact ->
            val selected = policy.enabled && artifact.coordinate in policy.includes && artifact.coordinate !in policy.excludes
            val attempt = if (selected) runCatching {
                require(artifact.plainJar) { "ANDROID_OR_NON_JAR_ARTIFACT" }
                require(!reflection) { "UNRESOLVED_REFLECTION_OR_CLASS_NAME_OBSERVATION" }
                require(artifact.classes.isNotEmpty()) { "NO_CLASS_INPUT" }
                require(artifact.originalEntries.keys.all { path -> path.endsWith(".class") ||
                    path.equals("META-INF/MANIFEST.MF", true) || Regex("(?i)(?:META-INF/)?(?:LICENSE|NOTICE|COPYING)(?:[._-].*)?").matches(path) }) { "RESOURCE_SERVICE_OR_SIGNATURE_CONTRACT" }
                val manifest = artifact.originalEntries.entries.firstOrNull { it.key.equals("META-INF/MANIFEST.MF", true) }?.value
                if (manifest != null) {
                    val parsed = java.util.jar.Manifest(manifest.inputStream())
                    require(parsed.entries.isEmpty() && parsed.mainAttributes.keys.all { it.toString().lowercase() in setOf("manifest-version", "created-by", "built-by", "build-jdk", "build-jdk-spec") }) { "JAR_MANIFEST_NAME_CONTRACT" }
                }
                val names = artifact.classes.keys
                require(names.all { name -> classes[name]?.contentEquals(artifact.classes.getValue(name)) == true }) { "EFFECTIVE_CLASS_PROVENANCE_NOT_CLOSED" }
                names.forEach { name -> requireUtility(nodes.getValue(name), names) }
                nodes.values.forEach { node -> requireOnlyStaticReferences(node, names) }
                val current = names.sorted().associateWith { name -> name.substringBeforeLast('/') + "/H" + Sha256.hex(seed + ("dependency-v1:${artifact.coordinate}:$name").toByteArray()).take(24) }
                require(current.values.none { it in classes || it in aliases.values }) { "DEPENDENCY_ALIAS_COLLISION" }
                current
            } else null
            attempt?.getOrNull()?.let { aliases.putAll(it) }
            mapOf("coordinate" to artifact.coordinate, "selected" to selected, "transformed" to (attempt?.isSuccess == true),
                "reason" to if (!selected) "OUTSIDE_EXPLICIT_COORDINATE_ALLOWLIST" else attempt?.exceptionOrNull()?.message.orEmpty().ifEmpty { "CLOSED_STATELESS_JAVA_UTILITY" },
                "classCount" to artifact.classes.size, "relocatedClasses" to (attempt?.getOrNull() ?: emptyMap<String, String>()),
                "finalDexBenefit" to "MEASURE_AFTER_R8_REMOVAL_AND_INLINING")
        }.toMutableList()
        (policy.includes - policy.excludes - artifacts.map { it.coordinate }.toSet()).sorted().forEach {
            rows += mapOf("coordinate" to it, "selected" to policy.enabled, "transformed" to false, "reason" to "COORDINATE_NOT_RESOLVED")
        }
        val selected = rows.count { it["selected"] == true }
        val count = rows.count { it["transformed"] == true }
        val coverage = if (selected == 0) 0.0 else count.toDouble() / selected
        require(!policy.enabled || coverage >= policy.minimumCoverage) { "dependency relocation coverage $coverage is below ${policy.minimumCoverage}" }
        val result = classes.toSortedMap().entries.associate { (name, before) ->
            val after = PreR8Relocation.transform(before, aliases)
            if (aliases.isNotEmpty()) PreR8Relocation.verify(before, after, aliases)
            (aliases[name] ?: name) to after
        }
        require(result.size == classes.size)
        return DependencyPlan(aliases, result, mapOf("schemaVersion" to 1, "enabled" to policy.enabled, "selected" to selected,
            "transformed" to count, "coverage" to coverage, "entries" to rows, "classInverseProof" to true,
            "scope" to "Closed stateless Java utilities only; original dependency coordinates and artifacts remain unchanged"))
    }

    private fun requireUtility(node: ClassNode, names: Set<String>) {
        require(node.name.contains('/') && node.superName == "java/lang/Object" && node.interfaces.isEmpty() &&
            node.access and (Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL) == (Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL) &&
            node.access and (Opcodes.ACC_INTERFACE or Opcodes.ACC_ENUM or Opcodes.ACC_ANNOTATION) == 0 &&
            node.outerClass == null && node.innerClasses.isEmpty() && node.nestHostClass == null && node.nestMembers.isNullOrEmpty() &&
            node.fields.isEmpty() && node.visibleAnnotations.isNullOrEmpty() && node.invisibleAnnotations.isNullOrEmpty()) { "STATE_TYPE_SERIALIZATION_OR_METADATA_CONTRACT" }
        node.methods.forEach { method ->
            if (method.name == "<init>") {
                require(method.access and Opcodes.ACC_PRIVATE != 0 && method.desc == "()V") { "PUBLIC_CONSTRUCTION_CONTRACT" }
                val code = method.instructions.filter { it.opcode >= 0 }
                require(code.size == 3 && code[0] is VarInsnNode && code[0].opcode == Opcodes.ALOAD && (code[0] as VarInsnNode).`var` == 0 &&
                    code[1] is MethodInsnNode && (code[1] as MethodInsnNode).let { it.opcode == Opcodes.INVOKESPECIAL && it.owner == "java/lang/Object" && it.name == "<init>" && it.desc == "()V" } &&
                    code[2].opcode == Opcodes.RETURN) { "NONTRIVIAL_CONSTRUCTOR" }
            } else {
                require(method.name != "<clinit>" && method.access and Opcodes.ACC_STATIC != 0 &&
                    method.access and (Opcodes.ACC_NATIVE or Opcodes.ACC_SYNCHRONIZED or Opcodes.ACC_ABSTRACT) == 0) { "INSTANCE_NATIVE_OR_INITIALIZATION_CONTRACT" }
                require((Type.getArgumentTypes(method.desc).toList() + Type.getReturnType(method.desc)).all { it.sort in Type.VOID..Type.DOUBLE || it.descriptor == "Ljava/lang/String;" }) { "PUBLIC_TYPE_ESCAPE" }
                require(method.visibleAnnotations.isNullOrEmpty() && method.invisibleAnnotations.isNullOrEmpty() && method.annotationDefault == null) { "ANNOTATION_CONTRACT" }
                method.instructions.forEach { insn ->
                    require(insn !is InvokeDynamicInsnNode && insn !is FieldInsnNode && insn !is TypeInsnNode && insn !is MultiANewArrayInsnNode) { "DYNAMIC_OR_STATEFUL_UTILITY" }
                    if (insn is LdcInsnNode) require(insn.cst is String || insn.cst is Number) { "CLASS_LITERAL_OR_DYNAMIC_CONSTANT" }
                    if (insn is MethodInsnNode) require(insn.opcode == Opcodes.INVOKESTATIC && (insn.owner in names || insn.owner in setOf("java/lang/Math", "java/lang/StrictMath", "java/lang/Integer", "java/lang/Long", "java/lang/Float", "java/lang/Double", "java/lang/Boolean"))) { "UNPROVEN_EXTERNAL_UTILITY_CALL" }
                }
            }
        }
    }

    private fun requireOnlyStaticReferences(source: ClassNode, names: Set<String>) {
        val clone = ClassNode()
        source.accept(clone)
        if (clone.name in names) {
            val original = clone.name
            clone.name = "hardening/proof/Utility"
            clone.methods.forEach { method -> method.localVariables?.filter { it.name == "this" && it.desc == "L$original;" }?.forEach { it.desc = "Lhardening/proof/Utility;" } }
        }
        clone.methods.forEach { method -> method.instructions.forEach { insn ->
            if (insn is MethodInsnNode && insn.owner in names) {
                require(insn.opcode == Opcodes.INVOKESTATIC && insn.name != "<init>") { "NON_STATIC_DEPENDENCY_REFERENCE" }
                insn.owner = "hardening/proof/Utility"
            }
            if (insn is LdcInsnNode && insn.cst is String) require(names.none { it.substringAfterLast('/') in (insn.cst as String) }) { "UNRESOLVED_DEPENDENCY_NAME_STRING" }
        } }
        val writer = ClassWriter(0)
        clone.accept(writer)
        val text = writer.toByteArray().toString(Charsets.ISO_8859_1)
        require(names.none { it in text || it.replace('/', '.') in text }) { "TYPE_ESCAPE_OR_UNSUPPORTED_CLASS_REFERENCE" }
    }
    private fun read(bytes: ByteArray) = ClassNode().also { ClassReader(bytes).accept(it, 0) }
}
