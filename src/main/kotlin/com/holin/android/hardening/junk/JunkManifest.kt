package com.holin.android.hardening.junk

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult
import org.w3c.dom.Document
import org.w3c.dom.Element

internal object JunkManifest {
    const val ANDROID = "http://schemas.android.com/apk/res/android"

    fun parse(bytes: ByteArray): Document = DocumentBuilderFactory.newInstance().apply {
        isNamespaceAware = true
        setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        setFeature("http://xml.org/sax/features/external-general-entities", false)
        setFeature("http://xml.org/sax/features/external-parameter-entities", false)
        setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "")
        setAttribute("http://javax.xml.XMLConstants/property/accessExternalSchema", "")
    }.newDocumentBuilder().parse(ByteArrayInputStream(bytes))

    fun fragment(classes: List<JunkClass>): String = "<manifest xmlns:android=\"$ANDROID\"><application>\n" +
        classes.filter { it.layout != null }.joinToString("\n") {
            "<activity android:name=\"${it.name}\" android:exported=\"false\" android:enabled=\"false\"/>"
        } + "\n</application></manifest>\n"

    fun applicationName(input: ByteArray): String {
        val document = parse(input)
        val applications = document.getElementsByTagName("application")
        require(applications.length == 1) { "junkCode requires exactly one application element" }
        val name = (applications.item(0) as Element).getAttributeNS(ANDROID, "name")
        val packageName = document.documentElement.getAttribute("package")
        return when {
            name.isEmpty() -> "android.app.Application"
            name.startsWith('.') -> packageName + name
            '.' !in name -> "$packageName.$name"
            else -> name
        }
    }

    fun merge(input: ByteArray, fragment: ByteArray, runtime: JunkRuntime?): ByteArray {
        val document = parse(input)
        val applications = document.getElementsByTagName("application")
        require(applications.length == 1) { "junkCode requires exactly one application element" }
        val application = applications.item(0) as Element
        if (runtime != null && applicationName(input) == "android.app.Application") {
            application.setAttributeNS(ANDROID, "android:name", runtime.entryClass)
        }
        val additions = parse(fragment).getElementsByTagName("activity")
        val packageName = document.documentElement.getAttribute("package")
        val existing = application.childNodes.let { nodes -> (0 until nodes.length).mapNotNull { nodes.item(it) as? Element } }
            .map { it.getAttributeNS(ANDROID, "name") }.filter { it.isNotEmpty() }.map {
                if (it.startsWith('.')) packageName + it else if ('.' !in it) "$packageName.$it" else it
            }.toMutableSet()
        for (index in 0 until additions.length) {
            val addition = additions.item(index) as Element
            val name = addition.getAttributeNS(ANDROID, "name")
            require(existing.add(name)) { "junkCode component conflicts with existing manifest: $name" }
            require(addition.getAttributeNS(ANDROID, "enabled") == "false" && addition.getAttributeNS(ANDROID, "exported") == "false")
            application.appendChild(document.importNode(addition, true))
        }
        val output = ByteArrayOutputStream()
        TransformerFactory.newInstance().apply {
            setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "")
            setAttribute("http://javax.xml.XMLConstants/property/accessExternalStylesheet", "")
        }.newTransformer().transform(DOMSource(document), StreamResult(output))
        return output.toByteArray()
    }
}
