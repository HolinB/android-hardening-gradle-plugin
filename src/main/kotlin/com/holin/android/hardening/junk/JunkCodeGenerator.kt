package com.holin.android.hardening.junk

import com.holin.android.hardening.state.Sha256
import com.holin.android.hardening.state.StrictJson
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Label
import org.objectweb.asm.Opcodes.*

internal data class JunkClass(val name: String, val methods: List<String>, val layout: String?)
internal data class JunkResource(val type: String, val name: String, val value: String = "")

internal data class JunkCodeInventory(
    val variant: String,
    val namespace: String,
    val policy: JunkCodePolicy,
    val lineageSeedSha256: String,
    val contentSaltSha256: String,
    val classes: List<JunkClass>,
    val resources: List<JunkResource>,
    val files: Map<String, String>,
    val generatedBytes: Long,
    val runtime: JunkRuntime?,
) {
    fun encode(): String = JsonOutput.toJson(linkedMapOf(
        "schemaVersion" to 2, "generatorVersion" to JunkCodePolicy.GENERATOR_VERSION,
        "variant" to variant, "namespace" to namespace, "policy" to policy.toMap(),
        "lineageSeedSha256" to lineageSeedSha256, "contentSaltSha256" to contentSaltSha256,
        "classes" to classes.map { linkedMapOf("name" to it.name, "methods" to it.methods, "layout" to it.layout) },
        "resources" to resources.map { linkedMapOf("type" to it.type, "name" to it.name, "value" to it.value) },
        "files" to files, "generatedBytes" to generatedBytes,
        "runtime" to runtime?.toMap(),
    )) + "\n"

    companion object {
        fun read(path: Path): JunkCodeInventory {
            val text = Files.readString(path)
            StrictJson.validateDocument(text)
            val data = JsonSlurper().parseText(text) as Map<*, *>
            require(data["schemaVersion"] == 2 && data["generatorVersion"] == JunkCodePolicy.GENERATOR_VERSION) {
                "unsupported junkCode inventory version"
            }
            val policy = JunkCodePolicy.decode(JsonOutput.toJson(data["policy"]))
            val classes = (data["classes"] as List<*>).map { value ->
                val row = value as Map<*, *>
                JunkClass(row["name"] as String, (row["methods"] as List<*>).map { it as String }, row["layout"] as String?)
            }
            val resources = (data["resources"] as List<*>).map { value ->
                val row = value as Map<*, *>
                JunkResource(row["type"] as String, row["name"] as String, row["value"] as String)
            }
            require(classes.size.toLong() == policy.classCount.toLong() + policy.activityCount &&
                classes.count { it.layout != null } == policy.activityCount &&
                classes.all { it.methods.size == policy.methodCountPerClass && it.methods.distinct().size == it.methods.size } &&
                classes.map { it.name }.distinct().size == classes.size) { "junkCode class inventory does not match its policy" }
            require(resources.groupingBy { it.type }.eachCount() == mapOf(
                "layout" to policy.activityCount, "drawable" to policy.drawableCount, "string" to policy.stringCount,
            ).filterValues { it > 0 } && resources.map { it.type to it.name }.distinct().size == resources.size) {
                "junkCode resource inventory does not match its policy"
            }
            val runtime = (data["runtime"] as? Map<*, *>)?.let(JunkRuntime::decode)
            require((runtime != null) == classes.any { it.methods.isNotEmpty() }) { "junkCode runtime entry missing or unexpected" }
            runtime?.validate(classes)
            return JunkCodeInventory(
                data["variant"] as String, data["namespace"] as String, policy,
                data["lineageSeedSha256"] as String, data["contentSaltSha256"] as String,
                classes, resources, (data["files"] as Map<*, *>).entries.associate { it.key as String to it.value as String },
                (data["generatedBytes"] as Number).toLong(), runtime,
            )
        }
    }
}

/** Generates only plugin-owned payload. Names use lineage entropy; bodies use invocation entropy. */
internal object JunkCodeGenerator {
    fun generate(
        policy: JunkCodePolicy,
        namespace: String,
        variant: String,
        seed: ByteArray,
        salt: ByteArray,
        output: Path,
    ): JunkCodeInventory {
        require(policy.enabled) { "junkCode generation is disabled" }
        require(namespace.matches(Regex("[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)*"))) { "invalid junkCode namespace" }
        require(seed.size == 32 && salt.size == 32) { "junkCode requires 32-byte seeds" }
        require(!Files.exists(output)) { "junkCode staging directory must be new" }
        Files.createDirectories(output)
        fun bytes(key: ByteArray, purpose: String): ByteArray = Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, "HmacSHA256"))
            doFinal("hardening-junk-v1\u0000$namespace\u0000$variant\u0000$purpose".toByteArray(Charsets.UTF_8))
        }
        fun token(purpose: String): String = Sha256.hex(bytes(seed, purpose)).take(24)
        val root = "$namespace.hjn${token("package")}"
        val prefix = "hjn_${token("resource")}_"
        val methods = (0 until policy.methodCountPerClass).map { "m${token("method/$it")}" }
        val classes = (0 until (policy.classCount + policy.activityCount)).map { index ->
            val activity = index >= policy.classCount
            JunkClass("$root.p${index % policy.packageCount}.C${token("class/$index")}", methods,
                if (activity) "${prefix}layout_${index - policy.classCount}" else null)
        }
        val resources = buildList {
            classes.mapNotNull { it.layout }.forEach { add(JunkResource("layout", it)) }
            repeat(policy.drawableCount) { add(JunkResource("drawable", "${prefix}drawable_$it")) }
            repeat(policy.stringCount) { add(JunkResource("string", "${prefix}string_$it", Sha256.hex(bytes(salt, "string/$it")))) }
        }
        val runtime = JunkRuntime.create(classes) { "$root.C${token("runtime/$it")}" }
        ZipOutputStream(Files.newOutputStream(output.resolve("classes.jar"))).use { zip ->
            classes.sortedBy { it.name }.forEach { item ->
                val owner = item.name.replace('.', '/')
                val writer = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
                val parent = if (item.layout == null) "java/lang/Object" else "android/app/Activity"
                writer.visit(V1_8, ACC_PUBLIC or ACC_FINAL or ACC_SUPER, owner, null, parent, null)
                writer.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null).apply {
                    visitCode(); visitVarInsn(ALOAD, 0); visitMethodInsn(INVOKESPECIAL, parent, "<init>", "()V", false)
                    visitInsn(RETURN); visitMaxs(0, 0); visitEnd()
                }
                item.methods.forEachIndexed { index, method ->
                    val constant = ByteBuffer.wrap(bytes(salt, "${item.name}/$method")).int
                    val target = classes.firstOrNull()?.takeIf { index > 0 }
                    writeMethod(writer, method, index % 5, constant, target)
                }
                if (item.layout != null) writer.visitMethod(ACC_PROTECTED, "onCreate", "(Landroid/os/Bundle;)V", null, null).apply {
                    visitCode(); visitVarInsn(ALOAD, 0); visitVarInsn(ALOAD, 1)
                    visitMethodInsn(INVOKESPECIAL, parent, "onCreate", "(Landroid/os/Bundle;)V", false)
                    visitVarInsn(ALOAD, 0)
                    visitFieldInsn(GETSTATIC, namespace.replace('.', '/') + "/R\$layout", item.layout, "I")
                    visitMethodInsn(INVOKEVIRTUAL, "android/app/Activity", "setContentView", "(I)V", false)
                    visitInsn(RETURN); visitMaxs(0, 0); visitEnd()
                }
                writer.visitEnd()
                zip.putNextEntry(ZipEntry("$owner.class").apply { time = 0L })
                zip.write(writer.toByteArray()); zip.closeEntry()
            }
            runtime?.groups?.sortedBy { it.name }?.forEach { group ->
                zip.putNextEntry(ZipEntry(group.name.replace('.', '/') + ".class").apply { time = 0L })
                zip.write(JunkRuntimeBytecode.generate(runtime, group, ByteBuffer.wrap(bytes(salt, "runtime/initial-value")).int))
                zip.closeEntry()
            }
        }
        fun write(relative: String, text: String) {
            val file = output.resolve(relative)
            Files.createDirectories(file.parent); Files.writeString(file, text)
        }
        val strings = resources.filter { it.type == "string" }
        val drawables = resources.filter { it.type == "drawable" }
        resources.filter { it.type == "layout" }.forEachIndexed { index, resource ->
            val text = strings.getOrNull(index % strings.size.coerceAtLeast(1))?.let { "@string/${it.name}" } ?: ""
            val background = drawables.getOrNull(index % drawables.size.coerceAtLeast(1))?.let { " android:background=\"@drawable/${it.name}\"" } ?: ""
            write("res/layout/${resource.name}.xml", "<TextView xmlns:android=\"http://schemas.android.com/apk/res/android\" android:layout_width=\"match_parent\" android:layout_height=\"match_parent\" android:text=\"$text\"$background/>\n")
        }
        drawables.forEach { resource ->
            val color = Sha256.hex(bytes(salt, resource.name)).take(6)
            write("res/drawable/${resource.name}.xml", "<shape xmlns:android=\"http://schemas.android.com/apk/res/android\" android:shape=\"rectangle\"><solid android:color=\"#$color\"/></shape>\n")
        }
        if (strings.isNotEmpty()) write("res/values/${prefix}strings.xml", "<resources>\n" + strings.joinToString("\n") {
            "<string name=\"${it.name}\" translatable=\"false\">${it.value}</string>"
        } + "\n</resources>\n")
        Files.createDirectories(output.resolve("res"))
        if (resources.isNotEmpty()) write("res/raw/${prefix}keep.xml",
            "<resources xmlns:tools=\"http://schemas.android.com/tools\" tools:keep=\"${resources.joinToString(",") { "@${it.type}/${it.name}" }}\"/>\n")
        write("keep.pro", (classes.map { it.name } + runtime?.groups.orEmpty().map { it.name }).joinToString(
            "\n", "# Exact plugin-generated classes only; preserve runtime calls and their bodies.\n", "\n") { "-keep class $it { *; }" })
        write("AndroidManifest.xml", JunkManifest.fragment(classes))
        val files = Files.walk(output).use { paths -> paths.filter(Files::isRegularFile).sorted().toList() }
        val inventory = JunkCodeInventory(variant, namespace, policy, Sha256.hex(seed), Sha256.hex(salt), classes, resources,
            files.associate { output.relativize(it).toString().replace('\\', '/') to Sha256.file(it) }, files.sumOf(Files::size), runtime)
        write("inventory.json", inventory.encode())
        return inventory
    }

    private fun writeMethod(writer: ClassWriter, name: String, template: Int, constant: Int, target: JunkClass?) {
        writer.visitMethod(ACC_PUBLIC or ACC_STATIC, name, "(I)I", null, null).apply {
            visitCode()
            when (template) {
                1 -> {
                    val negative = Label()
                    visitVarInsn(ILOAD, 0); visitJumpInsn(IFLT, negative)
                    visitVarInsn(ILOAD, 0); visitLdcInsn(constant); visitInsn(IADD); visitInsn(IRETURN)
                    visitLabel(negative); visitVarInsn(ILOAD, 0); visitLdcInsn(constant); visitInsn(ISUB)
                }
                2 -> {
                    visitVarInsn(ILOAD, 0); visitVarInsn(ISTORE, 1)
                    visitInsn(ICONST_0); visitVarInsn(ISTORE, 2)
                    val loop = Label(); val end = Label()
                    visitLabel(loop); visitVarInsn(ILOAD, 2); visitIntInsn(BIPUSH, 8); visitJumpInsn(IF_ICMPGE, end)
                    visitVarInsn(ILOAD, 1); visitLdcInsn(constant); visitInsn(IXOR)
                    visitVarInsn(ILOAD, 2); visitInsn(IADD); visitVarInsn(ISTORE, 1)
                    visitIincInsn(2, 1); visitJumpInsn(GOTO, loop); visitLabel(end); visitVarInsn(ILOAD, 1)
                }
                3 -> {
                    val first = Label(); val second = Label(); val other = Label(); val end = Label()
                    visitVarInsn(ILOAD, 0); visitInsn(ICONST_3); visitInsn(IAND)
                    visitLookupSwitchInsn(other, intArrayOf(0, 1), arrayOf(first, second))
                    visitLabel(first); visitLdcInsn(constant); visitJumpInsn(GOTO, end)
                    visitLabel(second); visitLdcInsn(constant.inv()); visitJumpInsn(GOTO, end)
                    visitLabel(other); visitVarInsn(ILOAD, 0); visitLabel(end)
                }
                4 -> {
                    visitVarInsn(ILOAD, 0)
                    if (target != null) visitMethodInsn(INVOKESTATIC, target.name.replace('.', '/'), target.methods.first(), "(I)I", false)
                    visitLdcInsn(constant); visitInsn(IADD)
                }
                else -> {
                    visitVarInsn(ILOAD, 0); visitLdcInsn(constant); visitInsn(IXOR)
                    visitIntInsn(BIPUSH, 3); visitInsn(IUSHR)
                }
            }
            visitInsn(IRETURN); visitMaxs(0, 0); visitEnd()
        }
    }
}
