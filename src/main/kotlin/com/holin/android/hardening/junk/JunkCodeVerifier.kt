package com.holin.android.hardening.junk

import com.android.aapt.Resources
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.iface.Method
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import com.holin.android.hardening.state.AtomicFiles
import com.holin.android.hardening.state.Sha256
import groovy.json.JsonOutput
import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.zip.ZipFile

/** Checks delivered payload, not merely the generator's intermediate files. */
internal object JunkCodeVerifier {
    fun verifyAab(artifact: Path, inventory: JunkCodeInventory, report: Path) {
        val calls = verifyPayload(artifact, inventory, true)
        writeReport(artifact, inventory, report, "AAB", calls)
    }

    fun verifyApk(artifact: Path, inventory: JunkCodeInventory, aapt2: Path, report: Path) {
        val nonce = UUID.randomUUID().toString()
        val converted = artifact.resolveSibling(".junk-verify-$nonce.apk")
        val log = artifact.resolveSibling(".junk-verify-$nonce.log")
        try {
            val process = ProcessBuilder(aapt2.toString(), "convert", "--output-format", "proto", "-o", converted.toString(), artifact.toString())
                .redirectErrorStream(true).redirectOutput(log.toFile()).start()
            try {
                require(process.waitFor(120, TimeUnit.SECONDS)) { "junkCode APK resource verification timed out" }
                require(process.exitValue() == 0) { "junkCode APK resource conversion failed: ${Files.readString(log).take(4096)}" }
            } finally {
                if (process.isAlive) process.destroyForcibly().waitFor()
            }
            val calls = verifyPayload(converted, inventory, false)
            writeReport(artifact, inventory, report, "APK", calls)
        } finally {
            Files.deleteIfExists(converted)
            Files.deleteIfExists(log)
        }
    }

    private fun verifyPayload(artifact: Path, inventory: JunkCodeInventory, bundle: Boolean): Map<String, Any>? {
        return ZipFile(artifact.toFile()).use { zip ->
            val entries = zip.entries().asSequence().toList()
            require(entries.map { it.name }.distinct().size == entries.size) { "junkCode verification found duplicate ZIP entries" }
            val expected = inventory.classes.associateBy { "L${it.name.replace('.', '/')};" }
            val found = mutableSetOf<String>()
            val definitions = mutableMapOf<String, ClassDef>()
            val dexPattern = if (bundle) Regex("base/dex/classes(?:[0-9]+)?\\.dex") else Regex("classes(?:[0-9]+)?\\.dex")
            entries.filter { dexPattern.matches(it.name) }.forEach { entry ->
                val dex = zip.getInputStream(entry).use { DexBackedDexFile.fromInputStream(null, it.buffered()) }
                dex.classes.forEach classLoop@ { definition ->
                    require(definitions.putIfAbsent(definition.type, definition) == null) { "duplicate DEX class ${definition.type}" }
                    val item = expected[definition.type] ?: return@classLoop
                    require(found.add(definition.type)) { "duplicate generated class ${item.name}" }
                    require(definition.superclass == if (item.layout == null) "Ljava/lang/Object;" else "Landroid/app/Activity;") {
                        "junkCode superclass changed for ${item.name}"
                    }
                    val methods = definition.methods.associateBy { method ->
                        method.name + "(" + method.parameterTypes.joinToString("") + ")" + method.returnType
                    }
                    val signatures = item.methods.map { "$it(I)I" } + "<init>()V" +
                        if (item.layout == null) emptyList() else listOf("onCreate(Landroid/os/Bundle;)V")
                    require(methods.keys == signatures.toSet() && methods.values.all { it.implementation != null }) {
                        "junkCode methods were removed or changed for ${item.name}"
                    }
                }
            }
            require(found == expected.keys) { "junkCode classes missing from final artifact: ${(expected.keys - found).take(10)}" }
            val tablePath = if (bundle) "base/resources.pb" else "resources.pb"
            val table = zip.getInputStream(requireNotNull(zip.getEntry(tablePath))).use(Resources.ResourceTable::parseFrom)
            val resources = table.packageList.flatMap { pkg -> pkg.typeList.flatMap { type -> type.entryList.map { (type.name to it.name) to it } } }.toMap()
            inventory.resources.forEach { item ->
                val resource = requireNotNull(resources[item.type to item.name]) { "junkCode resource missing: ${item.type}/${item.name}" }
                val values = resource.configValueList
                require(values.isNotEmpty()) { "junkCode resource is empty: ${item.name}" }
                if (item.type == "string") {
                    require(values.any { it.value.item.str.value == item.value }) { "junkCode string value changed: ${item.name}" }
                } else {
                    require(values.any { it.value.item.hasFile() && zip.getEntry((if (bundle) "base/" else "") + it.value.item.file.path) != null }) {
                        "junkCode resource file missing: ${item.name}"
                    }
                }
            }
            val manifestPath = if (bundle) "base/manifest/AndroidManifest.xml" else "AndroidManifest.xml"
            val manifest = zip.getInputStream(requireNotNull(zip.getEntry(manifestPath))).use(Resources.XmlNode::parseFrom)
            val applications = manifest.element.childList.filter { it.hasElement() && it.element.name == "application" }
            require(applications.size == 1) { "junkCode final manifest has no unique application" }
            val activities = applications.single().element.childList.filter { it.hasElement() && it.element.name == "activity" }.map { it.element }
            fun attribute(element: Resources.XmlElement, name: String) = element.attributeList.singleOrNull {
                it.namespaceUri == JunkManifest.ANDROID && it.name == name
            }
            inventory.classes.filter { it.layout != null }.forEach { item ->
                val matches = activities.filter { attribute(it, "name")?.value == item.name }
                require(matches.size == 1) { "junkCode Activity missing or duplicated: ${item.name}" }
                val activity = matches.single()
                listOf("enabled", "exported").forEach { name ->
                    val value = requireNotNull(attribute(activity, name)) { "junkCode Activity is missing $name" }
                    require(value.value == "false" || (value.hasCompiledItem() && value.compiledItem.hasPrim() &&
                        value.compiledItem.prim.hasBooleanValue() && !value.compiledItem.prim.booleanValue)) {
                        "junkCode Activity must have $name=false: ${item.name}"
                    }
                }
                require(activity.childList.none { it.hasElement() && it.element.name == "intent-filter" }) {
                    "junkCode Activity must not have an intent filter"
                }
            }
            inventory.runtime?.let { runtime ->
                val declared = requireNotNull(attribute(applications.single().element, "name")) {
                    "junkCode final manifest has no Application call entry"
                }.value
                val packageName = manifest.element.attributeList.single { it.name == "package" }.value
                val applicationName = when {
                    declared.startsWith('.') -> packageName + declared
                    '.' !in declared -> "$packageName.$declared"
                    else -> declared
                }
                verifyCalls(runtime, inventory.classes, definitions, applicationName)
            }
        }
    }

    internal fun verifyCalls(runtime: JunkRuntime, classes: List<JunkClass>, definitions: Map<String, ClassDef>, application: String): Map<String, Any> {
        runtime.validate(classes)
        fun definition(name: String) = requireNotNull(definitions["L${name.replace('.', '/')};"]) { "junkCode call class missing: $name" }
        fun method(name: String, member: String, parameters: List<String>, returns: String): Method =
            requireNotNull(definition(name).methods.singleOrNull {
                it.name == member && it.parameterTypes.map(CharSequence::toString) == parameters && it.returnType == returns && it.implementation != null
            }) { "junkCode call method missing: $name.$member" }
        fun calls(method: Method): List<String> = method.implementation!!.instructions.mapNotNull { instruction ->
            if (instruction.opcode != Opcode.INVOKE_STATIC && instruction.opcode != Opcode.INVOKE_STATIC_RANGE) return@mapNotNull null
            val reference = (instruction as? ReferenceInstruction)?.reference as? MethodReference ?: return@mapNotNull null
            "${reference.definingClass}->${reference.name}(${reference.parameterTypes.joinToString("")})${reference.returnType}"
        }.toList()
        fun reference(owner: String, member: String, descriptor: String) = "L${owner.replace('.', '/')};->$member$descriptor"
        // AppComponentFactory can construct an Application with arguments. Inspect all
        // successful constructors without requiring the framework's default signature.
        val constructors = definition(application).methods.filter { constructor ->
            constructor.name == "<init>" && constructor.implementation?.instructions?.any { it.opcode == Opcode.RETURN_VOID } == true
        }
        require(constructors.isNotEmpty() && constructors.all {
            reference(runtime.entryClass, "run", "()V") in calls(it)
        }) {
            "junkCode is not called by every successful final Application constructor: $application"
        }
        require(calls(method(runtime.entryClass, "run", emptyList(), "V")) == listOf(reference(runtime.entryClass, "compute", "(I)I"))) {
            "junkCode runtime entry lost its computation call"
        }
        runtime.groups.forEach { group ->
            require(calls(method(group.name, "compute", listOf("I"), "I")) == group.targets.map { reference(it.owner, it.name, "(I)I") }) {
                "junkCode runtime call chain changed or lost methods: ${group.name}"
            }
        }
        val fields = definition(runtime.entryClass).fields.associateBy { it.name }
        require(fields["executed"]?.type == "Z" && fields["result"]?.type == "I") { "junkCode runtime execution state missing" }
        return linkedMapOf("status" to "PASS", "applicationClass" to application, "entryClass" to runtime.entryClass,
            "runtimeClasses" to runtime.groups.size, "reachableGeneratedMethods" to classes.sumOf { it.methods.size })
    }

    private fun writeReport(artifact: Path, inventory: JunkCodeInventory, report: Path, kind: String, calls: Map<String, Any>?) {
        val data = linkedMapOf("schemaVersion" to 2, "status" to "PASS", "artifactKind" to kind,
            "variant" to inventory.variant, "artifactSha256" to Sha256.file(artifact), "artifactBytes" to Files.size(artifact),
            "inventorySha256" to Sha256.hex(inventory.encode().toByteArray()), "contentSaltSha256" to inventory.contentSaltSha256,
            "classes" to inventory.classes.size, "generatedMethods" to inventory.classes.sumOf { it.methods.size },
            "activities" to inventory.classes.count { it.layout != null }, "resources" to inventory.resources.size,
            "runtimeCalls" to calls)
        AtomicFiles().replace(report, (JsonOutput.toJson(data) + "\n").toByteArray())
    }
}
