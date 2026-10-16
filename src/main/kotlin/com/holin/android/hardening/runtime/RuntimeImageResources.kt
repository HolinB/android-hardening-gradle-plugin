package com.holin.android.hardening.runtime

import com.android.aapt.Resources
import com.holin.android.hardening.artifact.BundleEntryReplacement
import com.holin.android.hardening.artifact.BundleSemanticVerifier
import com.holin.android.hardening.resources.ResourceInventoryEntry
import com.holin.android.hardening.resources.ResourceOrigin
import com.holin.android.hardening.resources.ResourceTableTransformResult
import com.holin.android.hardening.resources.ResourceType
import com.holin.android.hardening.state.Sha256
import org.objectweb.asm.ClassReader
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.LdcInsnNode
import java.util.Base64

/** The initial image reader contract is XML drawable inflation; raw bitmap readers stay excluded. */
object RuntimeImageReferences {
    fun audit(classes: Map<String, ByteArray>, namespace: String, names: Set<String>, xml: Map<String, String> = emptyMap()): Map<String, Set<String>> {
        if (names.isEmpty()) return emptyMap()
        val reasons = names.associateWith { linkedSetOf<String>() }.toMutableMap()
        val symbolOwner = namespace.replace('.', '/') + "/R\$drawable"
        val symbols = classes[symbolOwner]?.let { bytes -> ClassNode().also { ClassReader(bytes).accept(it, ClassReader.SKIP_CODE) } }
        val ids = symbols?.fields.orEmpty().filter { it.name in names && it.value is Int }.associate { it.value as Int to it.name }
        val bitmapContracts = linkedSetOf<String>()
        val parents = mutableMapOf<String, String?>()
        (names - ids.values.toSet()).forEach { reasons.getValue(it).add("MISSING_VARIANT_RESOURCE_SYMBOL") }
        classes.forEach { (owner, bytes) ->
            if (owner.substringAfterLast('/').startsWith("R$")) return@forEach
            val node = ClassNode().also { ClassReader(bytes).accept(it, ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES) }
            parents[owner] = node.superName
            if (node.methods.any { method -> method.instructions.any { instruction ->
                instruction is org.objectweb.asm.tree.TypeInsnNode && instruction.desc.endsWith("BitmapDrawable")
            } }) bitmapContracts.add(owner)
            node.methods.forEach { method -> method.instructions.forEach { instruction ->
                val selected = when (instruction) {
                    is LdcInsnNode -> ids[instruction.cst] ?: (instruction.cst as? String)?.takeIf { it in names }
                    is FieldInsnNode -> instruction.name.takeIf { instruction.owner.endsWith("/R\$drawable") && it in names }
                    else -> null
                }
                if (selected != null) reasons.getValue(selected).add("BYTECODE_IMAGE_READER:$owner#${method.name}${method.desc}")
            } }
        }
        val androidAttributes = setOf("background", "foreground", "src", "button", "checkMark", "drawable", "drawableStart", "drawableEnd",
            "drawableLeft", "drawableRight", "drawableTop", "drawableBottom")
        val factory = javax.xml.parsers.DocumentBuilderFactory.newInstance().apply {
            isNamespaceAware = true
            setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        }
        xml.forEach { (path, source) ->
            val document = factory.newDocumentBuilder().parse(org.xml.sax.InputSource(source.reader()))
            val elements = document.getElementsByTagName("*")
            for (index in 0 until elements.length) {
                val element = elements.item(index) as org.w3c.dom.Element
                val viewClass = (if (element.tagName == "view") element.getAttribute("class") else element.tagName).replace('.', '/')
                val bitmapOnlyView = generateSequence(viewClass) { parents[it] }.any { it in bitmapContracts }
                for (attributeIndex in 0 until element.attributes.length) {
                    val attribute = element.attributes.item(attributeIndex)
                    val name = attribute.nodeValue.removePrefix("@drawable/")
                    if (attribute.nodeValue != "@drawable/$name" || name !in names) continue
                    val supported = (attribute.namespaceURI == "http://schemas.android.com/apk/res/android" && attribute.localName in androidAttributes) ||
                        (attribute.namespaceURI == "http://schemas.android.com/apk/res-auto" && attribute.localName == "srcCompat")
                    if (!supported || bitmapOnlyView || element.tagName in setOf("bitmap", "nine-patch", "adaptive-icon", "animation-list")) {
                        reasons.getValue(name).add("UNADAPTED_XML_IMAGE_READER:$path:${element.tagName}:${attribute.nodeName}")
                    }
                }
            }
        }
        return reasons
    }
}

data class RuntimeImageRecord(val oldPath: String, val newPath: String, val originalFileType: Int, val density: Int, val helper: String)
data class RuntimeImagePlan(val table: ResourceTableTransformResult, val replacements: List<BundleEntryReplacement>,
    val records: Map<String, RuntimeImageRecord>, val report: Map<String, Any>)

object RuntimeImageResources {
    fun plan(entries: Map<String, ByteArray>, inventory: List<ResourceInventoryEntry>, table: ResourceTableTransformResult,
        closure: RuntimeClosure?, key: ByteArray, salt: ByteArray): RuntimeImagePlan {
        val policy = closure?.policy?.images ?: RuntimeImagePolicy()
        if (!policy.enabled) return RuntimeImagePlan(table, emptyList(), emptyMap(), mapOf("enabled" to false))
        val originalTable = Resources.ResourceTable.parseFrom(entries.getValue("base/resources.pb"))
        val references = linkedSetOf<Int>()
        fun collect(message: com.google.protobuf.Message) {
            if (message is Resources.Reference && message.id != 0) references.add(message.id)
            message.allFields.values.forEach { value ->
                when (value) {
                    is com.google.protobuf.Message -> collect(value)
                    is List<*> -> value.filterIsInstance<com.google.protobuf.Message>().forEach(::collect)
                }
            }
        }
        // Values, themes, and manifest resources may be read by the system or by raw
        // bitmap APIs. Only ordinary layout/drawable inflation is enabled in this version.
        collect(originalTable)
        entries.filterKeys { it.endsWith("AndroidManifest.xml") || (it.endsWith(".xml") && "/res/layout" !in it && "/res/drawable" !in it) }
            .values.forEach { bytes -> runCatching { Resources.XmlNode.parseFrom(bytes) }.getOrNull()?.let(::collect) }
        entries.filterKeys { it.endsWith(".xml") && "/res/drawable" in it }.values.forEach { bytes ->
            val xml = runCatching { Resources.XmlNode.parseFrom(bytes) }.getOrNull()
            if (xml != null && xml.element.name !in setOf("selector", "layer-list", "inset", "clip", "scale", "rotate")) collect(xml)
        }
        val configs = originalTable.packageList.flatMap { it.typeList }.flatMap { it.entryList }.flatMap { entry ->
            entry.configValueList.filter { it.value.hasItem() && it.value.item.hasFile() }.map {
                "base/" + it.value.item.file.path to (it.value.item.file.typeValue to it.config.density)
            }
        }.toMap()
        val selected = inventory.filter { it.type == ResourceType.DRAWABLE && policy.accepts(it.name) && it.aabPath != null &&
            (it.aabPath.endsWith(".png", true) || it.aabPath.endsWith(".webp", true)) }.distinctBy { it.aabPath }
        val records = linkedMapOf<String, RuntimeImageRecord>()
        val replacements = mutableListOf<BundleEntryReplacement>()
        val rows = selected.map { resource ->
            val path = requireNotNull(resource.aabPath)
            val original = entries.getValue(path)
            val reason = when {
                resource.origin != ResourceOrigin.OWNED -> "NOT_OWNED"
                resource.externallyNamed || resource.notificationIcon -> "EXTERNAL_OR_SYSTEM_RESOURCE"
                resource.animation || animated(original, path) -> "ANIMATED_IMAGE"
                path.endsWith(".9.png", true) || ninePatch(original) -> "NINE_PATCH"
                resource.resourceId in references -> "VALUE_THEME_MANIFEST_OR_RAW_BITMAP_REFERENCE"
                resource.name !in requireNotNull(closure).images -> "UNADAPTED_BYTECODE_READER"
                path !in table.zipPathRenames -> "RESOURCE_NAMING_CLOSURE_MISSING"
                path !in configs -> "RESOURCE_CONFIGURATION_MISSING"
                else -> "ENCRYPTED_XML_DRAWABLE"
            }
            if (reason == "ENCRYPTED_XML_DRAWABLE") {
                val renamed = table.zipPathRenames.getValue(path)
                val destination = renamed.substringBeforeLast('.') + ".xml"
                require(destination !in entries && records.values.none { it.newPath == destination }) { "protected image output collides: $destination" }
                val configuration = configs.getValue(path)
                val record = RuntimeImageRecord(path, destination, configuration.first, configuration.second, closure!!.helper)
                val encrypted = RuntimeEnvelope.encrypt(original, key, "image:$path:${Sha256.hex(salt)}")
                val stub = stub(record, encrypted)
                verify(original, stub, record, key)
                records[path] = record
                replacements.add(BundleEntryReplacement(path, destination, stub, BundleSemanticVerifier.IMAGE_RUNTIME_EQUIVALENCE))
            }
            mapOf("name" to resource.name, "id" to resource.resourceId.toUInt().toString(16), "path" to path,
                "inputBytes" to original.size, "inputSha256" to Sha256.hex(original), "transformed" to (path in records), "reason" to reason)
        }
        val originalBytes = selected.sumOf { entries.getValue(requireNotNull(it.aabPath)).size.toLong() }
        val protectedBytes = records.keys.sumOf { entries.getValue(it).size.toLong() }
        val countCoverage = if (selected.isEmpty()) 0.0 else records.size.toDouble() / selected.size
        val byteCoverage = if (originalBytes == 0L) 0.0 else protectedBytes.toDouble() / originalBytes
        require(countCoverage + 1e-12 >= policy.minimumCoverage && byteCoverage + 1e-12 >= policy.minimumCoverage) {
            "runtime image count/byte coverage $countCoverage/$byteCoverage is below ${policy.minimumCoverage}"
        }
        val updated = rewriteTable(table.resourcesPb, records.values, false)
        val paths = table.zipPathRenames.mapValues { (old, renamed) -> records[old]?.newPath ?: renamed }
        val logicalPaths = table.logicalZipPathRenames.mapValues { (old, renamed) -> records[old]?.newPath ?: renamed }
        return RuntimeImagePlan(ResourceTableTransformResult(updated, paths, logicalPaths, table.report), replacements, records,
            mapOf("enabled" to true, "selected" to selected.size, "transformed" to records.size, "selectedBytes" to originalBytes,
                "protectedBytes" to protectedBytes, "countCoverage" to countCoverage, "byteCoverage" to byteCoverage,
                "formatConversionCount" to 0, "entries" to rows))
    }

    private fun stub(record: RuntimeImageRecord, encrypted: ByteArray): ByteArray {
        val element = Resources.XmlElement.newBuilder().setName("drawable")
        // Android binary XML's UTF-8 string pool limits individual strings to 32767
        // bytes. Independent base64 chunks remain aligned to complete four-byte groups.
        val chunks = Base64.getEncoder().encodeToString(encrypted).chunked(16384)
        val attributes = mapOf("class" to (record.helper.replace('/', '.') + "\$Image"),
            "density" to record.density.toString(), "digest" to Sha256.hex(encrypted), "chunks" to chunks.size.toString()) +
            chunks.mapIndexed { index, value -> "data$index" to value }
        attributes.forEach { (name, value) ->
            element.addAttribute(Resources.XmlAttribute.newBuilder().setName(name).setValue(value))
        }
        return Resources.XmlNode.newBuilder().setElement(element).build().toByteArray()
    }

    fun verify(before: ByteArray, after: ByteArray, record: RuntimeImageRecord, key: ByteArray) {
        val xml = Resources.XmlNode.parseFrom(after)
        val attributes = xml.element.attributeList.associate { it.name to it.value }
        val chunks = attributes.getValue("chunks").toInt()
        require(chunks in 1..4096)
        require(attributes.keys == setOf("class", "density", "digest", "chunks") + (0 until chunks).map { "data$it" } && xml.element.attributeCount == 4 + chunks)
        val encrypted = Base64.getDecoder().decode((0 until chunks).joinToString("") { attributes.getValue("data$it") })
        require(after.contentEquals(stub(record, encrypted))) { "protected drawable XML contains unexpected attributes or children" }
        require(RuntimeEnvelope.decrypt(encrypted, key).contentEquals(before)) { "protected drawable original pixels or format changed" }
    }

    fun normalizeTable(bytes: ByteArray, records: Collection<RuntimeImageRecord>): ByteArray = rewriteTable(bytes, records, true)

    private fun rewriteTable(bytes: ByteArray, records: Collection<RuntimeImageRecord>, restore: Boolean): ByteArray {
        if (records.isEmpty()) return bytes
        val byPath = records.associateBy { (if (restore) it.newPath else it.newPath.substringBeforeLast('.') + it.oldPath.substring(it.oldPath.lastIndexOf('.'))).removePrefix("base/") }
        val table = Resources.ResourceTable.parseFrom(bytes).toBuilder()
        val seen = linkedSetOf<String>()
        table.packageBuilderList.forEach { pkg -> pkg.typeBuilderList.forEach { type -> type.entryBuilderList.forEach { entry ->
            entry.configValueBuilderList.forEach { config ->
                if (config.value.hasItem() && config.value.item.hasFile()) {
                    val file = config.valueBuilder.itemBuilder.fileBuilder
                    byPath[file.path]?.let { record ->
                        seen.add(record.oldPath)
                        if (restore) {
                            require(file.type == Resources.FileReference.Type.PROTO_XML)
                            file.typeValue = record.originalFileType
                        } else {
                            require(file.typeValue == record.originalFileType)
                            file.path = record.newPath.removePrefix("base/")
                            file.type = Resources.FileReference.Type.PROTO_XML
                        }
                    }
                }
            }
        } } }
        require(seen == records.mapTo(linkedSetOf()) { it.oldPath }) { "protected image table references are not closed" }
        return table.build().toByteArray()
    }

    private fun animated(bytes: ByteArray, path: String): Boolean = if (path.endsWith(".png", true)) pngChunks(bytes).any { it == "acTL" }
        else String(bytes, Charsets.ISO_8859_1).contains("ANIM")
    private fun ninePatch(bytes: ByteArray): Boolean = pngChunks(bytes).any { it == "npTc" }
    private fun pngChunks(bytes: ByteArray): List<String> {
        if (bytes.size < 8 || bytes[0] != 0x89.toByte()) return emptyList()
        val names = mutableListOf<String>()
        var offset = 8
        while (offset + 12 <= bytes.size) {
            val size = java.nio.ByteBuffer.wrap(bytes, offset, 4).int
            if (size < 0 || size.toLong() + offset + 12 > bytes.size) return listOf("INVALID", "acTL")
            names.add(String(bytes, offset + 4, 4, Charsets.US_ASCII))
            offset += size + 12
        }
        return names
    }
}
