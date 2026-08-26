package com.holin.android.hardening.similarity

import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.instruction.Instruction
import com.android.tools.smali.dexlib2.iface.instruction.OffsetInstruction
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.instruction.formats.PackedSwitchPayload
import com.android.tools.smali.dexlib2.iface.instruction.formats.SparseSwitchPayload
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import com.android.tools.smali.dexlib2.iface.reference.StringReference
import com.holin.android.hardening.artifact.BundleZipRewriter
import com.holin.android.hardening.state.Sha256
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Locale
import java.util.zip.ZipFile

data class OwnedResourceKey(
    val resourceId: Int,
    val qualifier: String,
) {
    init {
        require(resourceId >= 0) { "owned resource ID must not be negative" }
        require('/' !in qualifier && '\\' !in qualifier) { "owned resource qualifier must not contain path separators" }
    }
}

data class OwnedResourceLocation(
    val entryName: String,
    val aabPath: String,
    val apkPath: String,
    val semanticHash: String,
) {
    init {
        require(entryName.isNotBlank() && '/' !in entryName && '\\' !in entryName) {
            "owned resource entry name must be a single nonblank ZIP path component"
        }
        BundleZipRewriter.requireSafeUniqueEntryNames(listOf(aabPath, apkPath))
        require(SHA_256.matches(semanticHash)) { "owned resource semanticHash must be lowercase SHA-256" }
    }
}

data class OwnedArtifactAnalysisRequest(
    val ordinaryAab: Path,
    val hardenedAab: Path,
    val ordinaryUniversalApk: Path,
    val hardenedUniversalApk: Path,
    val ownedDescriptors: Collection<String>,
    val ordinaryOwnedResources: Map<OwnedResourceKey, OwnedResourceLocation>,
    val hardenedOwnedResources: Map<OwnedResourceKey, OwnedResourceLocation>,
) {
    init {
        require(ownedDescriptors.isNotEmpty()) { "owned descriptors must not be empty" }
        require(ownedDescriptors.size == ownedDescriptors.toSet().size) { "owned descriptors must not contain duplicates" }
        require(ownedDescriptors.all(OWNED_DESCRIPTOR::matches)) { "owned descriptors must be exact class descriptors" }
        require(ordinaryOwnedResources.isNotEmpty() && hardenedOwnedResources.isNotEmpty()) {
            "owned resource locations must not be empty"
        }
        requireUniqueResourceLocations(ordinaryOwnedResources, "ordinary")
        requireUniqueResourceLocations(hardenedOwnedResources, "hardened")
    }

    private companion object {
        val OWNED_DESCRIPTOR = Regex("L[^;\\[\\]()]+;")

        fun requireUniqueResourceLocations(
            resources: Map<OwnedResourceKey, OwnedResourceLocation>,
            side: String,
        ) {
            val locationPairs = resources.values.map { it.aabPath to it.apkPath }
            require(locationPairs.size == locationPairs.toSet().size) {
                "$side owned resources contain duplicate AAB/APK resource location pairs"
            }
        }
    }
}

class OwnedArtifactAnalyzer {
    fun analyzePair(request: OwnedArtifactAnalysisRequest): Pair<OwnedArtifactProfile, OwnedArtifactProfile> {
        val descriptors = request.ownedDescriptors.toSet()
        val ordinaryAab = readArchive(
            request.ordinaryAab,
            ArtifactKind.AAB,
            request.ordinaryOwnedResources.values.mapTo(linkedSetOf(), OwnedResourceLocation::aabPath),
        )
        val ordinaryApk = readArchive(
            request.ordinaryUniversalApk,
            ArtifactKind.APK,
            request.ordinaryOwnedResources.values.mapTo(linkedSetOf(), OwnedResourceLocation::apkPath),
        )
        val hardenedAab = readArchive(
            request.hardenedAab,
            ArtifactKind.AAB,
            request.hardenedOwnedResources.values.mapTo(linkedSetOf(), OwnedResourceLocation::aabPath),
        )
        val hardenedApk = readArchive(
            request.hardenedUniversalApk,
            ArtifactKind.APK,
            request.hardenedOwnedResources.values.mapTo(linkedSetOf(), OwnedResourceLocation::apkPath),
        )
        return profile(
            request.ordinaryAab,
            request.ordinaryUniversalApk,
            ordinaryAab,
            ordinaryApk,
            descriptors,
            request.ordinaryOwnedResources,
            "ordinary",
        ) to profile(
            request.hardenedAab,
            request.hardenedUniversalApk,
            hardenedAab,
            hardenedApk,
            descriptors,
            request.hardenedOwnedResources,
            "hardened",
        )
    }

    private fun profile(
        aabPath: Path,
        apkPath: Path,
        aab: Archive,
        apk: Archive,
        descriptors: Set<String>,
        resources: Map<OwnedResourceKey, OwnedResourceLocation>,
        side: String,
    ): OwnedArtifactProfile {
        val aabCode = analyzeDex(aab, descriptors)
        val apkCode = analyzeDex(apk, descriptors)
        require(aabCode.descriptors == apkCode.descriptors) { "$side AAB/APK owned descriptors differ" }
        require(aabCode.methods == apkCode.methods) { "$side AAB/APK owned method fingerprints differ" }
        val ownedResources = resources.entries.sortedWith(
            compareBy<Map.Entry<OwnedResourceKey, OwnedResourceLocation>> { it.key.resourceId }
                .thenBy { it.key.qualifier },
        ).map { (key, location) -> resourceFingerprint(key, location, aab, apk, side) }
        return OwnedArtifactProfile(
            aabSha256 = Sha256.file(aabPath),
            aabSize = Files.size(aabPath),
            universalApkSha256 = Sha256.file(apkPath),
            universalApkSize = Files.size(apkPath),
            methods = apkCode.methods,
            resources = ownedResources,
        )
    }

    private fun readArchive(path: Path, kind: ArtifactKind, ownedResourcePaths: Set<String>): Archive {
        require(Files.isRegularFile(path)) { "${kind.label} analysis input is missing: $path" }
        return ZipFile(path.toFile()).use { zip ->
            val entries = zip.entries().asSequence().toList()
            BundleZipRewriter.requireSafeUniqueEntryNames(entries.map { it.name })
            Archive(
                kind,
                entries.filterNot { it.isDirectory }
                    .filter { entry -> kind.dexPath.matches(entry.name) || entry.name in ownedResourcePaths }
                    .associate { entry ->
                        entry.name to zip.getInputStream(entry).use { it.readBytes() }
                    },
            )
        }
    }

    private fun analyzeDex(archive: Archive, requested: Set<String>): DexAnalysis {
        val found = linkedSetOf<String>()
        val methods = linkedMapOf<String, MethodFingerprint>()
        archive.entries.asSequence()
            .filter { (path, _) -> archive.kind.dexPath.matches(path) }
            .sortedBy { it.key }
            .forEach { (dexPath, bytes) ->
                val dex = try {
                    DexBackedDexFile(Opcodes.getDefault(), bytes)
                } catch (failure: RuntimeException) {
                    throw IllegalArgumentException("invalid ${archive.kind.label} DEX entry $dexPath", failure)
                }
                dex.classes.asSequence().filter { it.type in requested }.forEach { classDef ->
                    require(found.add(classDef.type)) {
                        "duplicate owned descriptor ${classDef.type} across ${archive.kind.label} multidex"
                    }
                    classDef.methods.asSequence().mapNotNull { method ->
                        val instructions = method.implementation?.instructions?.toList() ?: return@mapNotNull null
                        if (instructions.size < MIN_METHOD_INSTRUCTIONS) return@mapNotNull null
                        val descriptor = "(${method.parameterTypes.joinToString("")})${method.returnType}"
                        val identifier = "${method.definingClass}->${method.name}$descriptor"
                        identifier to fingerprint(identifier, instructions)
                    }.forEach { (identifier, fingerprint) ->
                        require(methods.put(identifier, fingerprint) == null) {
                            "duplicate owned method $identifier in ${archive.kind.label}"
                        }
                    }
                }
            }
        val missing = requested - found
        require(missing.isEmpty()) {
            "${archive.kind.label} is missing requested owned descriptors: ${missing.sorted().joinToString()}"
        }
        return DexAnalysis(found, methods.values.sortedBy(MethodFingerprint::identifier))
    }

    internal fun fingerprint(identifier: String, instructions: List<Instruction>): MethodFingerprint {
        val opcodes = instructions.map { opcodeFamily(it.opcode.name) }
        val apiCategories = mutableListOf<String>()
        val stringCategories = mutableListOf<String>()
        instructions.forEach { instruction ->
            val reference = (instruction as? ReferenceInstruction)?.reference
            if (reference is MethodReference) platformApiCategory(reference.definingClass)?.let(apiCategories::add)
            if (reference is StringReference) stringCategories += stringLengthCategory(reference.string.length)
        }
        val blockSignature = basicBlockSignature(instructions, opcodes)
        val canonical = listOf(
            opcodes.joinToString("\u001f"),
            blockSignature.joinToString("\u001f"),
            apiCategories.joinToString("\u001f"),
            stringCategories.joinToString("\u001f"),
        ).joinToString("\u0000")
        return MethodFingerprint(
            identifier = identifier,
            instructionCount = instructions.size,
            canonicalHash = sha256(canonical.toByteArray()),
            opcodeTokens = opcodes,
            apiCalls = apiCategories,
            constants = stringCategories,
            blockSignature = blockSignature,
        )
    }

    private fun resourceFingerprint(
        key: OwnedResourceKey,
        location: OwnedResourceLocation,
        aab: Archive,
        apk: Archive,
        side: String,
    ): OwnedResourceFingerprint {
        val aabParts = resourcePathParts(location.aabPath, ArtifactKind.AAB)
        val apkParts = resourcePathParts(location.apkPath, ArtifactKind.APK)
        require(aabParts == apkParts && aabParts.entryName == location.entryName) {
            "$side owned resource ${key.resourceId} has inconsistent AAB/APK type, qualifier, or entry name"
        }
        require(aabParts.qualifier == key.qualifier) {
            "$side owned resource ${key.resourceId} qualifier does not match its path"
        }
        requireNotNull(aab.entries[location.aabPath]) {
            "$side AAB is missing owned resource ${location.aabPath}"
        }
        val apkBytes = requireNotNull(apk.entries[location.apkPath]) {
            "$side APK is missing owned resource ${location.apkPath}"
        }
        return OwnedResourceFingerprint(
            resourceId = key.resourceId,
            qualifier = key.qualifier,
            originalEntryName = location.entryName,
            currentEntryName = location.entryName,
            aabPath = location.aabPath,
            apkPath = location.apkPath,
            size = apkBytes.size.toLong(),
            sha256 = Sha256.hex(apkBytes),
            semanticHash = location.semanticHash,
        )
    }

    private fun resourcePathParts(path: String, kind: ArtifactKind): ResourcePathParts {
        val match = requireNotNull(kind.resourcePath.matchEntire(path)) {
            "owned resource path must be inside ${kind.label} res/: $path"
        }
        val directory = match.groupValues[1]
        val entryName = match.groupValues[2]
        val type = directory.substringBefore('-')
        val qualifier = directory.substringAfter('-', "")
        require(RESOURCE_TYPE.matches(type)) { "owned resource path has an invalid type: $path" }
        return ResourcePathParts(type, qualifier, entryName)
    }

    private fun basicBlockSignature(instructions: List<Instruction>, opcodes: List<String>): List<String> {
        val addresses = IntArray(instructions.size)
        var address = 0
        instructions.forEachIndexed { index, instruction ->
            addresses[index] = address
            address += instruction.codeUnits
        }
        val instructionIndexByAddress = addresses.withIndex().associate { it.value to it.index }
        val blockStartAddresses = linkedSetOf(addresses.first())
        instructions.indices.forEach { index ->
            branchTargets(index, instructions, opcodes, addresses, instructionIndexByAddress)
                .filterTo(blockStartAddresses, instructionIndexByAddress::containsKey)
            if (opcodes[index] in CONTROL_FLOW_FAMILIES && index + 1 < instructions.size) {
                blockStartAddresses += addresses[index + 1]
            }
        }
        val starts = blockStartAddresses.sorted()
        val startIndexByAddress = starts.associateWith(instructionIndexByAddress::getValue)
        val blockByStartAddress = starts.withIndex().associate { it.value to it.index }
        val edges = starts.indices.flatMap { blockIndex ->
            val endIndex = starts.getOrNull(blockIndex + 1)?.let(startIndexByAddress::getValue) ?: instructions.size
            val tailIndex = endIndex - 1
            val nextStart = starts.getOrNull(blockIndex + 1)
            when (opcodes[tailIndex]) {
                "if" -> buildList {
                    branchTargets(tailIndex, instructions, opcodes, addresses, instructionIndexByAddress)
                        .firstOrNull()?.let { add(CfgEdge(blockIndex, blockByStartAddress.getValue(it), "conditional-true")) }
                    nextStart?.let { add(CfgEdge(blockIndex, blockByStartAddress.getValue(it), "conditional-false")) }
                }
                "goto" -> branchTargets(tailIndex, instructions, opcodes, addresses, instructionIndexByAddress)
                    .take(1)
                    .map { CfgEdge(blockIndex, blockByStartAddress.getValue(it), "goto") }
                "switch" -> buildList {
                    branchTargets(tailIndex, instructions, opcodes, addresses, instructionIndexByAddress)
                        .distinct()
                        .sorted()
                        .forEach { add(CfgEdge(blockIndex, blockByStartAddress.getValue(it), "switch-case")) }
                    nextStart?.let { add(CfgEdge(blockIndex, blockByStartAddress.getValue(it), "switch-default")) }
                }
                "return", "throw" -> emptyList()
                else -> nextStart?.let { listOf(CfgEdge(blockIndex, blockByStartAddress.getValue(it), "fallthrough")) }
                    ?: emptyList()
            }
        }
        return starts.indices.map { blockIndex ->
            val startIndex = startIndexByAddress.getValue(starts[blockIndex])
            val endIndex = starts.getOrNull(blockIndex + 1)?.let(startIndexByAddress::getValue) ?: instructions.size
            val incoming = edges.filter { it.target == blockIndex }
            val outgoing = edges.filter { it.source == blockIndex }
            listOf(
                "block:${ordinalToken(blockIndex)}:${blockPosition(blockIndex, starts.size)}",
                "size:${sizeCategory(endIndex - startIndex)}",
                "in:${ordinalToken(incoming.size)}:${incoming.map(CfgEdge::kind).sorted().joinToString("+")}",
                "out:${ordinalToken(outgoing.size)}:${outgoing.sortedWith(compareBy(CfgEdge::kind).thenBy(CfgEdge::target))
                    .joinToString("+") { edge ->
                        "${edge.kind}-${edgeDirection(blockIndex, edge.target)}-${ordinalToken(edge.target)}"
                    }}",
            ).joinToString("|")
        }
    }

    private fun branchTargets(
        index: Int,
        instructions: List<Instruction>,
        opcodes: List<String>,
        addresses: IntArray,
        instructionIndexByAddress: Map<Int, Int>,
    ): List<Int> {
        val instruction = instructions[index] as? OffsetInstruction ?: return emptyList()
        val targetAddress = addresses[index] + instruction.codeOffset
        if (opcodes[index] != "switch") return listOf(targetAddress)
        val payloadIndex = instructionIndexByAddress[targetAddress] ?: return emptyList()
        val offsets = when (val payload = instructions[payloadIndex]) {
            is PackedSwitchPayload -> payload.switchElements.map { it.offset }
            is SparseSwitchPayload -> payload.switchElements.map { it.offset }
            else -> return emptyList()
        }
        return offsets.map { offset -> addresses[index] + offset }
    }

    private fun blockPosition(index: Int, count: Int): String = when {
        count == 1 -> "only"
        index == 0 -> "entry"
        index == count - 1 -> "exit"
        else -> "middle"
    }

    private fun sizeCategory(size: Int): String = when {
        size <= 1 -> "one"
        size <= 3 -> "small"
        size <= 8 -> "medium"
        else -> "large"
    }

    private fun ordinalToken(value: Int): String {
        var remaining = value
        return buildString {
            do {
                append(('a'.code + remaining % 26).toChar())
                remaining /= 26
            } while (remaining > 0)
        }.reversed()
    }

    private fun edgeDirection(source: Int, target: Int): String = when {
        target == source -> "self"
        target < source -> "backward"
        target == source + 1 -> "next"
        else -> "forward"
    }

    private fun opcodeFamily(raw: String): String {
        val name = raw.lowercase(Locale.ROOT).substringBefore('/')
        if (name.endsWith("-payload")) return "payload"
        return OPCODE_FAMILIES.firstOrNull { (prefix, _) -> name.startsWith(prefix) }?.second
            ?: name.substringBefore('-')
    }

    private fun platformApiCategory(descriptor: String): String? = when {
        descriptor.startsWith("Landroid/view/") || descriptor.startsWith("Landroid/widget/") ||
            descriptor.startsWith("Landroid/graphics/") -> "android-ui"
        descriptor.startsWith("Landroid/os/") -> "android-runtime"
        descriptor.startsWith("Landroid/net/") -> "android-network"
        descriptor.startsWith("Landroid/content/") -> "android-content"
        descriptor.startsWith("Landroid/media/") -> "android-media"
        descriptor.startsWith("Landroid/database/") -> "android-data"
        descriptor.startsWith("Landroid/security/") -> "android-security"
        descriptor.startsWith("Landroid/") -> "android-other"
        descriptor.startsWith("Ljava/io/") || descriptor.startsWith("Ljava/nio/") -> "java-io"
        descriptor.startsWith("Ljava/net/") -> "java-network"
        descriptor.startsWith("Ljava/util/concurrent/") -> "java-concurrency"
        descriptor.startsWith("Ljava/util/") -> "java-collections"
        descriptor.startsWith("Ljava/security/") || descriptor.startsWith("Ljavax/crypto/") -> "java-security"
        descriptor.startsWith("Ljava/lang/reflect/") -> "java-reflection"
        descriptor.startsWith("Ljava/lang/") -> "java-language"
        descriptor.startsWith("Ljava/") -> "java-other"
        descriptor.startsWith("Ljavax/") -> "javax"
        else -> null
    }

    private fun stringLengthCategory(length: Int): String = when {
        length == 0 -> "string:empty"
        length <= 8 -> "string:short"
        length <= 32 -> "string:medium"
        length <= 128 -> "string:long"
        else -> "string:very-long"
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { "%02x".format(it) }

    private data class Archive(val kind: ArtifactKind, val entries: Map<String, ByteArray>)
    private data class DexAnalysis(val descriptors: Set<String>, val methods: List<MethodFingerprint>)
    private data class ResourcePathParts(val type: String, val qualifier: String, val entryName: String)
    private data class CfgEdge(val source: Int, val target: Int, val kind: String)

    private enum class ArtifactKind(
        val label: String,
        val dexPath: Regex,
        val resourcePath: Regex,
    ) {
        AAB("AAB", Regex("^[^/]+/dex/classes(?:[0-9]+)?\\.dex$"), Regex("^[^/]+/res/([^/]+)/([^/]+)$")),
        APK("APK", Regex("^classes(?:[0-9]+)?\\.dex$"), Regex("^res/([^/]+)/([^/]+)$")),
    }

    private companion object {
        const val MIN_METHOD_INSTRUCTIONS = 12
        val RESOURCE_TYPE = Regex("[a-z][a-z0-9_]*")
        val CONTROL_FLOW_FAMILIES = setOf("if", "goto", "switch", "return", "throw")
        val OPCODE_FAMILIES = listOf(
            "invoke" to "invoke", "const" to "const", "move" to "move", "if-" to "if",
            "goto" to "goto", "return" to "return", "iget" to "field-get", "sget" to "field-get",
            "iput" to "field-put", "sput" to "field-put", "aget" to "array-get", "aput" to "array-put",
            "new-" to "new", "packed-switch" to "switch", "sparse-switch" to "switch",
        )
    }
}
