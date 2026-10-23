package com.holin.android.hardening.runtime

import com.holin.android.hardening.state.Sha256
import org.xml.sax.Attributes
import org.xml.sax.InputSource
import org.xml.sax.Locator
import org.xml.sax.helpers.DefaultHandler
import java.io.StringReader
import javax.xml.parsers.SAXParserFactory

data class RuntimeStringIssue(val code: String, val location: Map<String, Any> = emptyMap(), val consumer: String = "") {
    fun values(): Map<String, Any> = mapOf("code" to code, "location" to location,
        "suggestion" to when (code) {
            "EXPLICIT_EXCLUSION" -> "Keep the documented exclusion or explicitly move this resource to another group."
            "XML_OR_RESOURCE_ALIAS_REFERENCE", "COMPILED_XML_OR_RESOURCE_REFERENCE" -> "Remove the unsupported XML/resource reference or explicitly exclude this resource."
            "ABSENT_AFTER_R8", "RESOURCE_NOT_IN_SYMBOLS", "NO_TRACEABLE_PLATFORM_GETSTRING" -> "Check this variant's resource name and all compiled consumers."
            "NOT_OWNED" -> "Check resource ownership; third-party resources cannot be selected implicitly."
            else -> "Use a supported reader and a closed resource-ID flow, or explicitly exclude this resource."
        }) + if (consumer.isEmpty()) emptyMap() else mapOf("consumer" to consumer)
}

class RuntimeStringCoverageException(val diagnostic: Map<String, Any>, message: String) : IllegalArgumentException(message)

object RuntimeStringDiagnostics {
    fun failures(policy: RuntimeProtectionPolicy, successful: Set<String>): List<String> = buildList {
        val legacy = coverage(policy.strings, successful)
        if ((policy.strings.isNotEmpty() || !policy.hasStringGroups) && legacy < policy.minimumStringCoverage) {
            add("legacy coverage $legacy is below ${policy.minimumStringCoverage}")
        }
        val missing = policy.requiredStrings - successful
        if (missing.isNotEmpty()) add("${missing.size} required string(s) are unprotected: ${missing.sorted().joinToString()}")
    }

    fun report(policy: RuntimeProtectionPolicy, closed: Set<String>, transformed: Set<String>?,
        issues: Map<String, Collection<RuntimeStringIssue>>, readers: Map<String, Collection<Map<String, Any>>> = emptyMap(),
        namespace: String = "", stage: String = "READERS", eligible: Set<String> = transformed ?: closed): Map<String, Any> {
        val successful = eligible
        val failures = failures(policy, successful)
        val groups = linkedMapOf("legacy" to policy.strings, "required" to policy.requiredStrings,
            "candidate" to policy.candidateStrings, "excluded" to policy.excludedStrings.keys)
        return mapOf("schemaVersion" to 1, "stage" to stage, "status" to if (failures.isEmpty()) "PASS" else "FAIL",
            "failures" to failures, "configured" to policy.declaredStrings.size, "selected" to policy.selectedStrings.size,
            "closedReaders" to closed.intersect(policy.selectedStrings).size, "transformed" to transformed?.size.orZero(),
            "coverage" to coverage(policy.selectedStrings, successful), "finalArtifactVerified" to false,
            "eligible" to eligible.size, "excluded" to policy.excludedStrings.size,
            "groups" to groups.mapValues { (_, names) -> mapOf("configured" to names.size,
                "closedReaders" to names.intersect(closed).size, "eligible" to names.intersect(eligible).size,
                "excluded" to names.intersect(policy.excludedStrings.keys).size, "transformed" to transformed?.intersect(names)?.size.orZero(),
                "coverage" to coverage(names, successful), "unprotected" to (names - successful).size) },
            "entries" to policy.declaredStrings.sorted().map { name ->
                val excluded = name in policy.excludedStrings
                val reasons = if (excluded) listOf(RuntimeStringIssue("EXPLICIT_EXCLUSION")) else issues[name].orEmpty()
                mapOf("name" to name, "resource" to (if (namespace.isEmpty()) "" else "$namespace:") + "string/$name",
                    "stage" to stage, "group" to groups.entries.first { name in it.value }.key,
                    "status" to when { excluded -> "EXCLUDED"; name !in successful -> "UNPROTECTED"; transformed == null -> if (stage == "FINAL") "ELIGIBLE_PENDING_TRANSFORM" else "PENDING_FINAL_RESOURCE_CHECK"; else -> "TRANSFORMED" },
                    "closed" to (name in closed), "transformed" to (transformed?.contains(name) == true),
                    "reasons" to reasons.distinct().sortedBy { it.code + it.location.toString() + it.consumer }.map(RuntimeStringIssue::values),
                    "readers" to readers[name].orEmpty().distinct().sortedBy { it.toString() }) +
                    if (excluded) mapOf("exclusionReason" to policy.excludedStrings.getValue(name)) else emptyMap()
            })
    }

    fun transformed(report: Map<String, Any>, names: Set<String>): Map<String, Any> {
        @Suppress("UNCHECKED_CAST")
        val rows = (report.getValue("entries") as List<Map<String, Any>>).map { row ->
            if (row["name"] in names) row + mapOf("status" to "TRANSFORMED", "transformed" to true) else row
        }
        @Suppress("UNCHECKED_CAST")
        val groups = (report.getValue("groups") as Map<String, Map<String, Any>>).mapValues { (group, stats) ->
            stats + mapOf("transformed" to rows.count { it["group"] == group && it["transformed"] == true })
        }
        return report + mapOf("entries" to rows, "groups" to groups, "transformed" to names.size, "resourceTableInverseProof" to true)
    }

    fun requireCoverage(policy: RuntimeProtectionPolicy, successful: Set<String>, report: Map<String, Any>, reportPath: String = "") {
        val failures = failures(policy, successful)
        if (failures.isEmpty()) return
        val entries = report["entries"] as? List<*> ?: emptyList<Any>()
        val rejected = entries.filterIsInstance<Map<*, *>>().filter { it["status"] == "UNPROTECTED" }
        val examples = rejected.take(5).joinToString { row ->
            val reasons = (row["reasons"] as? List<*>)?.filterIsInstance<Map<*, *>>()?.map { it["code"] }.orEmpty()
            "${row["name"]}: ${reasons.joinToString()}"
        }
        throw RuntimeStringCoverageException(report, "runtime strings: ${failures.joinToString("; ")}; ${rejected.size} rejected" +
            (if (examples.isEmpty()) "" else "; $examples") + (if (reportPath.isEmpty()) "" else "; report: $reportPath"))
    }

    fun fingerprint(policy: RuntimeProtectionPolicy, namespace: String, classes: Map<String, ByteArray>, hierarchy: Map<String, ByteArray>, xml: Map<String, String>): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        fun field(value: String) { digest.update(value.toByteArray(Charsets.UTF_8)); digest.update(0.toByte()) }
        field(policy.encode()); field(namespace)
        listOf(classes, hierarchy).forEachIndexed { index, entries ->
            field(index.toString()); entries.toSortedMap().forEach { (name, bytes) -> field(name); field(Sha256.hex(bytes)) }
        }
        xml.toSortedMap().forEach { (name, text) -> field(name); field(Sha256.hex(text.toByteArray(Charsets.UTF_8))) }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun coverage(names: Set<String>, successful: Set<String>) = if (names.isEmpty()) 0.0 else names.intersect(successful).size.toDouble() / names.size
    private fun Int?.orZero() = this ?: 0
}

object RuntimeStringXmlReferences {
    fun scan(xml: Map<String, String>, selected: Set<String>): Map<String, List<RuntimeStringIssue>> {
        val result = linkedMapOf<String, MutableList<RuntimeStringIssue>>()
        val reference = Regex("(?<!\\\\)@(?:([A-Za-z0-9_.]+):)?string/([a-z][a-z0-9_]*)\\b")
        xml.toSortedMap().forEach { (path, text) ->
            var locator: Locator? = null
            fun inspect(value: String, line: Int, attribute: String = "") {
                val textValue = value.trim()
                val references = if (textValue.startsWith("@{") || textValue.startsWith("@={")) reference.findAll(textValue)
                    else listOfNotNull(reference.matchEntire(textValue)).asSequence()
                references.filter { it.groupValues[1] != "android" && it.groupValues[2] in selected }.forEach { match ->
                    result.getOrPut(match.groupValues[2]) { mutableListOf() }.add(RuntimeStringIssue("XML_OR_RESOURCE_ALIAS_REFERENCE",
                        mapOf("file" to path, "line" to line, "attribute" to attribute), match.value))
                }
            }
            try {
                val factory = SAXParserFactory.newInstance()
                factory.isNamespaceAware = true
                factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
                factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
                factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
                factory.newSAXParser().parse(InputSource(StringReader(text)), object : DefaultHandler() {
                    private val content = ArrayDeque<Pair<Int, StringBuilder>>()
                    override fun setDocumentLocator(value: Locator) { locator = value }
                    override fun startElement(uri: String, localName: String, qName: String, attributes: Attributes) {
                        val line = locator?.lineNumber ?: -1
                        content.addLast(line to StringBuilder())
                        for (index in 0 until attributes.length) if (attributes.getURI(index) != "http://schemas.android.com/tools") {
                            inspect(attributes.getValue(index), line, attributes.getQName(index))
                        }
                    }
                    override fun characters(ch: CharArray, start: Int, length: Int) { content.lastOrNull()?.second?.append(ch, start, length) }
                    override fun endElement(uri: String, localName: String, qName: String) { content.removeLast().let { inspect(it.second.toString(), it.first) } }
                })
            } catch (_: Exception) {
                selected.forEach { name -> result.getOrPut(name) { mutableListOf() }.add(RuntimeStringIssue("UNREADABLE_RESOURCE_XML",
                    mapOf("file" to path, "line" to (locator?.lineNumber ?: -1)))) }
            }
        }
        return result
    }
}
