package com.holin.android.hardening.device

import java.io.StringReader
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Element
import org.w3c.dom.Node
import org.xml.sax.InputSource

internal object DeviceAcceptanceConfigurationResolver {
    fun applicationId(explicit: String?, applicationIdFromVariant: Boolean, variantApplicationId: String?): String {
        explicit?.let { value ->
            require(value.isNotBlank()) { "deviceAcceptance.applicationId override must be nonblank" }
            return validatedApplicationId(value)
        }
        require(applicationIdFromVariant) {
            "deviceAcceptance.applicationId is absent and applicationIdFromVariant is false"
        }
        return validatedApplicationId(
            variantApplicationId?.takeIf(String::isNotBlank)
                ?: throw IllegalArgumentException("variant applicationId is unavailable"),
        )
    }

    fun launchActivity(
        explicit: String?,
        launchActivityFromManifest: Boolean,
        mergedManifestXml: String?,
        applicationId: String,
    ): String {
        explicit?.let { value ->
            require(value.isNotBlank()) { "deviceAcceptance.launchActivity override must be nonblank" }
            return normalizeActivity(value, applicationId)
        }
        require(launchActivityFromManifest) {
            "deviceAcceptance.launchActivity is absent and launchActivityFromManifest is false"
        }
        require(!mergedManifestXml.isNullOrBlank()) { "merged manifest is unavailable for launcher resolution" }
        val document = try {
            manifestFactory().newDocumentBuilder().parse(InputSource(StringReader(mergedManifestXml)))
        } catch (failure: Exception) {
            throw IllegalArgumentException("merged manifest is invalid", failure)
        }
        val launchers = buildSet {
            listOf("activity", "activity-alias").forEach { tag ->
                val elements = document.getElementsByTagName(tag)
                for (index in 0 until elements.length) {
                    val element = elements.item(index) as? Element ?: continue
                    if (element.hasLauncherIntentFilter()) {
                        val declared = element.getAttributeNS(ANDROID_NAMESPACE, "name")
                        require(declared.isNotBlank()) { "manifest launcher $tag is missing android:name" }
                        add(normalizeActivity(declared, applicationId))
                    }
                }
            }
        }.sorted()
        require(launchers.isNotEmpty()) { "merged manifest does not declare a launcher activity" }
        require(launchers.size == 1) { "merged manifest launcher is ambiguous: $launchers" }
        return launchers.single()
    }

    private fun Element.hasLauncherIntentFilter(): Boolean = childElements("intent-filter").any { filter ->
        val actions = filter.childElements("action")
            .map { it.getAttributeNS(ANDROID_NAMESPACE, "name") }
            .toSet()
        val categories = filter.childElements("category")
            .map { it.getAttributeNS(ANDROID_NAMESPACE, "name") }
            .toSet()
        MAIN_ACTION in actions && LAUNCHER_CATEGORY in categories
    }

    private fun Element.childElements(tagName: String): Sequence<Element> = sequence {
        var child: Node? = firstChild
        while (child != null) {
            if (child is Element && child.tagName == tagName) yield(child)
            child = child.nextSibling
        }
    }

    private fun normalizeActivity(declared: String, applicationId: String): String {
        require(declared.none(Char::isWhitespace) && '/' !in declared) {
            "device acceptance launch activity is malformed: $declared"
        }
        val normalized = when {
            declared.startsWith('.') -> applicationId + declared
            '.' !in declared -> "$applicationId.$declared"
            else -> declared
        }
        require(CLASS_NAME.matches(normalized)) { "device acceptance launch activity is malformed: $declared" }
        return normalized
    }

    private fun validatedApplicationId(value: String): String {
        require(APPLICATION_ID.matches(value)) { "device acceptance applicationId is malformed: $value" }
        return value
    }

    private fun manifestFactory(): DocumentBuilderFactory = DocumentBuilderFactory.newInstance().apply {
        isNamespaceAware = true
        setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        setFeature("http://xml.org/sax/features/external-general-entities", false)
        setFeature("http://xml.org/sax/features/external-parameter-entities", false)
        setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false)
        setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "")
        setAttribute("http://javax.xml.XMLConstants/property/accessExternalSchema", "")
        isXIncludeAware = false
        setExpandEntityReferences(false)
    }

    private const val ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"
    private const val MAIN_ACTION = "android.intent.action.MAIN"
    private const val LAUNCHER_CATEGORY = "android.intent.category.LAUNCHER"
    private val APPLICATION_ID = Regex("[A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)+")
    private val CLASS_NAME = Regex("[A-Za-z_][A-Za-z0-9_$]*(?:\\.[A-Za-z_][A-Za-z0-9_$]*)+")
}
