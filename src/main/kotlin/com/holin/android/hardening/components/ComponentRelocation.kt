package com.holin.android.hardening.components

import com.holin.android.hardening.state.Sha256
import com.holin.android.hardening.state.StrictJson
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.commons.ClassRemapper
import org.objectweb.asm.commons.Remapper
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.LdcInsnNode
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult
import org.w3c.dom.Element

data class ComponentPolicy(
    val enabled: Boolean = false,
    val includes: Set<String> = emptySet(),
    val excludes: Set<String> = emptySet(),
    val minimumCoverage: Double = 0.0,
) {
    init {
        require(minimumCoverage.isFinite() && minimumCoverage in 0.0..1.0)
        (includes + excludes).forEach { require(Regex("[A-Za-z_$][A-Za-z0-9_$.]*").matches(it)) }
        require(!enabled || includes.isNotEmpty()) { "components require an explicit class allowlist" }
    }
    fun encode(): String = JsonOutput.toJson(mapOf("schemaVersion" to 1, "enabled" to enabled,
        "includes" to includes.sorted(), "excludes" to excludes.sorted(), "minimumCoverage" to minimumCoverage))
    companion object {
        fun decode(text: String): ComponentPolicy {
            StrictJson.validateDocument(text)
            val p = JsonSlurper().parseText(text) as Map<*, *>
            require(p["schemaVersion"] == 1)
            return ComponentPolicy(p["enabled"] as Boolean, (p["includes"] as List<*>).map { it as String }.toSet(),
                (p["excludes"] as List<*>).map { it as String }.toSet(), (p["minimumCoverage"] as Number).toDouble())
        }
    }
}

data class ComponentPlan(val manifest: ByteArray, val relocations: Map<String, String>, val report: Map<String, Any>)

/** Changes only closed, private Activity identities. Old explicit intents retain a private alias. */
object ComponentRelocation {
    const val ANDROID = "http://schemas.android.com/apk/res/android"

    fun plan(
        manifest: ByteArray,
        namespace: String,
        policy: ComponentPolicy,
        seed: ByteArray,
        ownedClasses: Set<String>,
        sources: Map<String, String>,
        resourceXml: Map<String, String>,
    ): ComponentPlan {
        val document = parse(manifest)
        val application = document.getElementsByTagName("application").item(0) as? Element
            ?: error("merged manifest has no application")
        val components = (0 until application.childNodes.length).map { application.childNodes.item(it) }
            .filterIsInstance<Element>().filter { it.tagName in setOf("activity", "activity-alias", "service", "receiver", "provider") }
        val names = components.map { qualified(it.getAttributeNS(ANDROID, "name"), namespace) }
        val ambiguousNames = names.groupingBy { it }.eachCount().filterValues { it > 1 }.keys
        val aliases = linkedMapOf<String, String>()
        val rows = components.map { element ->
            val original = qualified(element.getAttributeNS(ANDROID, "name"), namespace)
            val scoped = policy.enabled && original in policy.includes && original !in policy.excludes
            val sourceName = original.replace('.', '/')
            val observations = sources.filterValues { text ->
                // A class-name string, reflection, or name-based persistence has no closed rewrite contract.
                text.contains("\"$original\"") || text.contains("\"$sourceName\"") ||
                    Regex("(?:getSimpleName|getCanonicalName|getName)\\s*\\(|\\.(?:simpleName|qualifiedName)\\b").containsMatchIn(text) ||
                    Regex("(?:Class\\.forName|loadClass|setClassName|flattenToString|unflattenFromString|writeSerializable|readSerializable)\\s*\\(").containsMatchIn(text)
            }.keys.sorted()
            val kotlinReferences = sources.filter { (path, text) -> path.endsWith(".kt") &&
                Regex("\\b" + Regex.escape(original.substringAfterLast('.')) + "\\b").containsMatchIn(text) }.keys.sorted()
            val xmlReferences = resourceXml.filterValues { original in it || sourceName in it }.keys.sorted()
            var reason = when {
                !policy.enabled -> "DISABLED"
                !scoped -> "OUTSIDE_EXPLICIT_ALLOWLIST"
                original in ambiguousNames -> "AMBIGUOUS_DUPLICATE_COMPONENT_IDENTITY"
                sourceName !in ownedClasses -> "SOURCE_OWNERSHIP_UNPROVEN"
                element.tagName != "activity" -> "PERSISTED_COMPONENT_IDENTITY_NO_COMPATIBILITY_ADAPTER"
                element.getAttributeNS(ANDROID, "exported") == "true" -> "EXTERNAL_COMPONENT_CONTRACT"
                element.getElementsByTagName("intent-filter").length != 0 -> "ACTION_CATEGORY_OR_DEEPLINK_CONTRACT"
                element.getAttributeNS(ANDROID, "exported").let { it.isNotBlank() && it != "false" } -> "DYNAMIC_EXPORTED_VALUE"
                observations.isNotEmpty() -> "UNRESOLVED_REFLECTION_OR_PERSISTENCE"
                kotlinReferences.isNotEmpty() -> "KOTLIN_METADATA_IDENTITY_ADAPTER_UNAVAILABLE"
                xmlReferences.isNotEmpty() -> "XML_OR_NAVIGATION_CLASS_REFERENCE"
                components.any { it.tagName == "activity-alias" && qualified(it.getAttributeNS(ANDROID, "targetActivity"), namespace) == original } -> "EXISTING_ALIAS_CONTRACT"
                else -> "PRIVATE_ACTIVITY_WITH_LEGACY_ALIAS"
            }
            if (reason == "PRIVATE_ACTIVITY_WITH_LEGACY_ALIAS") {
                val hash = Sha256.hex(seed + ("component-v1:$original").toByteArray())
                val alias = sourceName.substringBeforeLast('/') + "/H" + hash.take(24)
                require(alias !in ownedClasses && alias !in aliases.values && alias.replace('/', '.') !in names) { "component alias collision" }
                aliases[sourceName] = alias
            }
            linkedMapOf<String, Any>("type" to element.tagName, "original" to original, "selected" to scoped,
                "reason" to reason, "references" to (observations + kotlinReferences + xmlReferences),
                "output" to (aliases[sourceName]?.replace('/', '.') ?: original))
        }.toMutableList()
        policy.includes.filter { it !in names && it !in policy.excludes }.sorted().forEach { name ->
            rows += linkedMapOf("type" to "missing", "original" to name, "selected" to policy.enabled,
                "reason" to "NOT_IN_MERGED_MANIFEST", "output" to name, "references" to emptyList<String>())
        }
        val selected = rows.count { it["selected"] == true }
        val coverage = if (selected == 0) 0.0 else aliases.size.toDouble() / selected
        require(!policy.enabled || coverage >= policy.minimumCoverage) {
            "component coverage $coverage is below ${policy.minimumCoverage}; reasons: ${rows.filter { it["selected"] == true }}"
        }
        components.forEach { element ->
            val original = qualified(element.getAttributeNS(ANDROID, "name"), namespace)
            val alias = aliases[original.replace('.', '/')] ?: return@forEach
            element.setAttributeNS(ANDROID, "android:name", alias.replace('/', '.'))
            val legacy = document.createElement("activity-alias")
            legacy.setAttributeNS(ANDROID, "android:name", original)
            legacy.setAttributeNS(ANDROID, "android:targetActivity", alias.replace('/', '.'))
            legacy.setAttributeNS(ANDROID, "android:exported", "false")
            listOf("enabled", "permission", "icon", "label").forEach { attribute ->
                if (element.hasAttributeNS(ANDROID, attribute)) legacy.setAttributeNS(ANDROID, "android:$attribute", element.getAttributeNS(ANDROID, attribute))
            }
            application.insertBefore(legacy, element.nextSibling)
        }
        components.forEach { element ->
            val parent = qualified(element.getAttributeNS(ANDROID, "parentActivityName"), namespace)
            aliases[parent.replace('.', '/')]?.let { element.setAttributeNS(ANDROID, "android:parentActivityName", it.replace('/', '.')) }
        }
        val output = if (aliases.isEmpty()) manifest else serialize(document)
        verifyManifest(manifest, output, namespace, aliases)
        return ComponentPlan(output, aliases, mapOf("schemaVersion" to 1, "policy" to policy.encode(),
            "selected" to selected, "transformed" to aliases.size, "coverage" to coverage, "entries" to rows,
            "sourceSha256" to Sha256.hex(manifest), "outputSha256" to Sha256.hex(output),
            "actionsAndCategories" to "PRESERVED", "legacyActivityNames" to "PRIVATE_COMPATIBILITY_ALIAS"))
    }

    fun verifyManifest(before: ByteArray, after: ByteArray, namespace: String, aliases: Map<String, String>) {
        val original = parse(before)
        val candidate = parse(after)
        val all = candidate.getElementsByTagName("activity-alias")
        (0 until all.length).map { all.item(it) as Element }.forEach { element ->
            val name = qualified(element.getAttributeNS(ANDROID, "name"), namespace).replace('.', '/')
            if (name in aliases) {
                require(element.getAttributeNS(ANDROID, "targetActivity") == aliases.getValue(name).replace('/', '.'))
                require(element.getAttributeNS(ANDROID, "exported") == "false")
                val permitted = setOf("name", "targetActivity", "exported", "enabled", "permission", "icon", "label")
                require((0 until element.attributes.length).all { element.attributes.item(it).localName in permitted })
                element.parentNode.removeChild(element)
            }
        }
        val inverse = aliases.entries.associate { it.value.replace('/', '.') to it.key.replace('/', '.') }
        val elements = candidate.getElementsByTagName("*")
        (0 until elements.length).map { elements.item(it) as Element }.forEach { element ->
            listOf("name", "parentActivityName").forEach { attr ->
                val value = element.getAttributeNS(ANDROID, attr)
                inverse[value]?.let { canonical ->
                    val originalElements = original.getElementsByTagName(element.tagName)
                    val match = (0 until originalElements.length).map { originalElements.item(it) as Element }
                        .firstOrNull { qualified(it.getAttributeNS(ANDROID, attr), namespace) == canonical }
                        ?: error("unproven manifest class reference")
                    element.setAttributeNS(ANDROID, "android:$attr", match.getAttributeNS(ANDROID, attr))
                }
            }
        }
        require(canonical(original.documentElement) == canonical(candidate.documentElement)) { "component manifest changed unrelated semantics" }
    }

    private fun canonical(element: Element): Any = listOf(element.namespaceURI.orEmpty(), element.tagName,
        (0 until element.attributes.length).map { element.attributes.item(it) }.associate { it.nodeName to it.nodeValue }.toSortedMap(),
        (0 until element.childNodes.length).map { element.childNodes.item(it) }.mapNotNull {
            when { it is Element -> canonical(it); it.nodeType == org.w3c.dom.Node.TEXT_NODE && it.nodeValue.isNotBlank() -> it.nodeValue; else -> null }
        })

    private fun qualified(name: String, namespace: String): String = when {
        name.isBlank() -> ""
        name.startsWith('.') -> namespace + name
        '.' !in name -> "$namespace.$name"
        else -> name
    }

    private fun parse(bytes: ByteArray) = DocumentBuilderFactory.newInstance().apply {
        isNamespaceAware = true
        setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        setFeature("http://xml.org/sax/features/external-general-entities", false)
        setFeature("http://xml.org/sax/features/external-parameter-entities", false)
        setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "")
        setAttribute("http://javax.xml.XMLConstants/property/accessExternalSchema", "")
    }.newDocumentBuilder().parse(ByteArrayInputStream(bytes))

    private fun serialize(document: org.w3c.dom.Document): ByteArray = ByteArrayOutputStream().use { out ->
        TransformerFactory.newInstance().apply {
            setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "")
            setAttribute("http://javax.xml.XMLConstants/property/accessExternalStylesheet", "")
        }.newTransformer().transform(DOMSource(document), StreamResult(out))
        out.toByteArray()
    }
}

/** Shared pre-R8 descriptor transformation; string constants are never silently adapted. */
object PreR8Relocation {
    fun transform(bytes: ByteArray, mapping: Map<String, String>): ByteArray {
        if (mapping.isEmpty()) return bytes
        val writer = ClassWriter(0)
        val remapper = object : Remapper() {
            override fun map(internalName: String): String = mapping[internalName] ?: internalName

        }
        ClassReader(bytes).accept(ClassRemapper(writer, remapper), 0)
        return writer.toByteArray()
    }

    fun verify(before: ByteArray, after: ByteArray, mapping: Map<String, String>) {
        val normalizedBefore = transform(before, mapOf("hardening/UnreachableIdentity" to "hardening/UnreachableIdentity"))
        val restored = transform(after, mapping.entries.associate { it.value to it.key })
        require(normalizedBefore.contentEquals(restored)) { "pre-R8 class inverse proof failed: ${ClassReader(before).className}" }
    }

    fun requireClosedStrings(bytes: ByteArray, mapping: Map<String, String>) {
        val node = ClassNode()
        ClassReader(bytes).accept(node, 0)
        val forbidden = mapping.keys.flatMap { listOf(it, it.replace('/', '.')) }.toSet()
        val metadata = (node.visibleAnnotations.orEmpty() + node.invisibleAnnotations.orEmpty()).filter { it.desc == "Lkotlin/Metadata;" }
        require(metadata.none { annotation -> forbidden.any { name -> name in annotation.values.orEmpty().toString() } }) { "unadapted Kotlin metadata component identity" }
        require(node.fields.none { it.value is String && forbidden.any { name -> name in (it.value as String) } }) { "component identity in a field constant" }
        require(node.methods.none { method -> method.instructions.any { it is LdcInsnNode && it.cst is String && forbidden.any { name -> name in (it.cst as String) } } }) {
            "component identity in an unresolved bytecode string"
        }
        require(node.methods.none { it.access and org.objectweb.asm.Opcodes.ACC_NATIVE != 0 && node.name in mapping }) {
            "component has a native symbol contract"
        }
    }

    fun rewriteMappingLeft(text: String, mapping: Map<String, String>): String = text.lineSequence().joinToString("\n") { line ->
        if (line.startsWith('#') || " -> " !in line) line else {
            val split = line.indexOf(" -> ")
            replaceTypeNames(line.substring(0, split), mapping) + line.substring(split)
        }
    }

    fun replaceTypeNames(text: String, mapping: Map<String, String>): String {
        val dotted = mapping.entries.associate { it.key.replace('/', '.') to it.value.replace('/', '.') }
        return Regex("[A-Za-z_$][A-Za-z0-9_$.]*").replace(text) { match -> dotted[match.value] ?: match.value }
    }

    fun readPlan(text: String): Map<String, String> {
        StrictJson.validateDocument(text)
        val p = JsonSlurper().parseText(text) as Map<*, *>
        require(p["schemaVersion"] == 1)
        return (p["relocations"] as Map<*, *>).entries.associate { it.key as String to it.value as String }.also { m ->
            require(m.values.toSet().size == m.size)
            m.forEach { (from, to) ->
                require(Regex("[A-Za-z_$][A-Za-z0-9_$/]*").matches(from) && Regex("[A-Za-z_$][A-Za-z0-9_$/]*").matches(to))
                require(from.substringBeforeLast('/') == to.substringBeforeLast('/')) { "component relocation must preserve package access" }
            }
        }
    }
}
