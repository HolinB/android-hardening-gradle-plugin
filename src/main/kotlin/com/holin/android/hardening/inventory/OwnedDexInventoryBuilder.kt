package com.holin.android.hardening.inventory

import com.holin.android.hardening.HardeningOwnership
import java.nio.file.Files
import java.nio.file.Path

data class OwnedSourceClass(
    val originalDescriptor: String,
    val module: String,
    val source: Path,
    val kind: OwnedSourceClassKind = OwnedSourceClassKind.DECLARED_TYPE,
    val kotlinSourcePart: OwnedKotlinSourcePart? = null,
)

enum class OwnedSourceClassKind {
    DECLARED_TYPE,
    KOTLIN_FILE_FACADE,
    KOTLIN_MULTIFILE_FACADE,
    KOTLIN_MULTIFILE_PART,
}

data class OwnedKotlinSourcePart(
    val sourceFileName: String,
    val packageInternalName: String,
    val hasTopLevelJvmDeclaration: Boolean,
    val fileJvmName: String?,
    val multifileClass: Boolean,
    val expectedFacadeDescriptor: String,
    val expectedPartDescriptor: String?,
)

data class OwnedDexDescriptorProof(
    val outputDescriptor: String,
    val mappedOriginalDescriptors: Set<String>,
    val explicitMemberOwnerDescriptors: Set<String>,
    val sourceOriginalDescriptors: Set<String>,
    val sourceFiles: Set<Path>,
)

data class OwnedDexInventory(
    val sources: List<OwnedSourceClass>,
    val descriptorProofs: List<OwnedDexDescriptorProof>,
    val mixedOrUnownedMergedDescriptors: Set<String>,
) {
    val acceptedDexDescriptors: Set<String> = descriptorProofs
        .mapTo(sortedSetOf(), OwnedDexDescriptorProof::outputDescriptor)
    val accessCompatibilityDexDescriptors: Set<String> =
        (acceptedDexDescriptors + mixedOrUnownedMergedDescriptors).toSortedSet()

    init {
        require(descriptorProofs.map(OwnedDexDescriptorProof::outputDescriptor).distinct().size == descriptorProofs.size) {
            "owned DEX descriptor proof contains duplicate outputs"
        }
        val inventoriedSources = sources.groupBy(OwnedSourceClass::originalDescriptor)
        descriptorProofs.forEach { proof ->
            require(isObjectDescriptor(proof.outputDescriptor)) { "invalid proven output DEX descriptor" }
            require(proof.mappedOriginalDescriptors.isNotEmpty() && proof.sourceOriginalDescriptors.isNotEmpty()) {
                "owned DEX descriptor proof is incomplete"
            }
            require(proof.sourceFiles.isNotEmpty()) { "owned DEX descriptor proof has no source file" }
            require(proof.sourceOriginalDescriptors.all(inventoriedSources::containsKey)) {
                "owned DEX descriptor proof references a non-inventoried source"
            }
            require(
                (proof.mappedOriginalDescriptors + proof.explicitMemberOwnerDescriptors).all { mappedOriginal ->
                    proof.sourceOriginalDescriptors.any { sourceOriginal -> owns(sourceOriginal, mappedOriginal) }
                },
            ) { "owned DEX descriptor proof contains an unproven mapped owner" }
            require(
                proof.sourceOriginalDescriptors.flatMapTo(linkedSetOf()) { descriptor ->
                    inventoriedSources.getValue(descriptor).map(OwnedSourceClass::source)
                } == proof.sourceFiles,
            ) { "owned DEX descriptor proof source files are inconsistent" }
        }
        require(acceptedDexDescriptors.intersect(mixedOrUnownedMergedDescriptors).isEmpty()) {
            "owned DEX inventory has an ambiguous merged class"
        }
    }

    private fun isObjectDescriptor(value: String): Boolean =
        value.length >= 3 && value.startsWith('L') && value.endsWith(';') &&
            value.substring(1, value.lastIndex).none { it == '[' || it == '.' || it == ';' }

    private fun owns(sourceDescriptor: String, mappedOriginal: String): Boolean =
        mappedOriginal == sourceDescriptor || mappedOriginal.startsWith(sourceDescriptor.removeSuffix(";") + "${'$'}")
}

/** Pins only inventoried first-party classes against R8 optimizations that invalidate member mappings. */
class OwnedCodeOptimizationRules(
    repositoryRoot: Path,
    ownership: HardeningOwnership,
) {
    private val inventory = OwnedDexInventoryBuilder(repositoryRoot, ownership)

    fun render(): String = buildString {
        append("# Preserve the optimization shape of app-owned symbols across mapping reuse.\n")
        inventory.sourceInventory()
            .map(OwnedSourceClass::originalDescriptor)
            .distinct()
            .sorted()
            .forEach { descriptor ->
                val className = descriptor.substring(1, descriptor.lastIndex).replace('/', '.')
                append("-keep,allowobfuscation,allowshrinking class ")
                    .append(className)
                    .append(" { *; }\n")
                append("-keep,allowobfuscation,allowshrinking class ")
                    .append(className)
                    .append("${'$'}* { *; }\n")
            }
    }
}

/** Builds an exact post-R8 class allow-list from production source and the public mapping output. */
class OwnedDexInventoryBuilder(
    repositoryRoot: Path,
    private val ownership: HardeningOwnership,
    private val gitIgnoreMatcher: GitIgnoreMatcher = GitIgnoreMatcher(repositoryRoot),
) {
    private val root = repositoryRoot.toAbsolutePath().normalize()

    fun sourceInventory(): List<OwnedSourceClass> {
        val sourceFiles = collectSourceFiles()
        return sourceFiles.asSequence()
            .flatMap(::descriptorsForSource)
            .toList()
            .let(::withoutIncompleteMultifileGroups)
            .asSequence()
            .sortedWith(
                compareBy(
                    OwnedSourceClass::module,
                    OwnedSourceClass::originalDescriptor,
                    { it.source.toString() },
                    { it.kind.ordinal },
                ),
            )
            .toList()
            .also { sources ->
                require(sources.isNotEmpty()) { "no eligible owned production classes were found" }
                requireNoConflictingSourceDescriptors(sources)
            }
    }

    fun build(mappingText: String): OwnedDexInventory {
        val sources = sourceInventory()
        val sourcesByDescriptor = sources.groupBy(OwnedSourceClass::originalDescriptor)
        val mappings = parseClassMappings(mappingText)
        require(mappings.isNotEmpty()) { "R8 mapping contains no class mappings" }
        val proofs = mutableListOf<OwnedDexDescriptorProof>()
        val mixed = sortedSetOf<String>()
        mappings.groupBy(ClassMapping::outputDescriptor).toSortedMap().forEach { (output, group) ->
            val mappedOwners = group.map { mapping -> resolveSources(mapping.originalDescriptor, sourcesByDescriptor) }
            val explicitOwners = group.flatMap(ClassMapping::explicitMemberOwnerDescriptors)
                .map { owner -> resolveSources(owner, sourcesByDescriptor) }
            val allOwners = mappedOwners + explicitOwners
            val hasOwnedOriginal = mappedOwners.any { it != null }
            if (allOwners.all { it != null }) {
                val provenSources = allOwners.filterNotNull().flatten().toSet()
                proofs += OwnedDexDescriptorProof(
                    outputDescriptor = output,
                    mappedOriginalDescriptors = group.mapTo(sortedSetOf(), ClassMapping::originalDescriptor),
                    explicitMemberOwnerDescriptors = group.flatMapTo(
                        sortedSetOf(),
                        ClassMapping::explicitMemberOwnerDescriptors,
                    ),
                    sourceOriginalDescriptors = provenSources.mapTo(sortedSetOf(), OwnedSourceClass::originalDescriptor),
                    sourceFiles = provenSources.mapTo(linkedSetOf(), OwnedSourceClass::source),
                )
            } else if (hasOwnedOriginal) {
                mixed += output
            }
        }
        return OwnedDexInventory(sources, proofs, mixed)
    }

    private fun collectSourceFiles(): List<StaticAppSource> {
        ownership.modules.forEach { declaration ->
            (declaration.sourceRoots.javaDirectories + declaration.sourceRoots.kotlinDirectories)
                .forEach sourceRootLoop@{ sourceRoot ->
                    requireNoSymlinks(sourceRoot)
                    if (!Files.isDirectory(sourceRoot)) return@sourceRootLoop
                    Files.walk(sourceRoot).use { paths ->
                        paths.forEach(::requireNoSymlinks)
                    }
                }
        }
        return AppSourceInventory(root, ownership, gitIgnoreMatcher).scan()
            .filter { source -> source.kind == AppSourceKind.JAVA || source.kind == AppSourceKind.KOTLIN }
    }

    private fun requireNoSymlinks(path: Path) {
        val normalized = path.toAbsolutePath().normalize()
        require(normalized.startsWith(root)) { "owned source path is outside the repository: $normalized" }
        var current = root
        require(!Files.isSymbolicLink(current)) { "owned source path contains symbolic link: $current" }
        root.relativize(normalized).forEach { component ->
            current = current.resolve(component)
            require(!Files.isSymbolicLink(current)) { "owned source path contains symbolic link: $current" }
        }
    }

    private fun descriptorsForSource(source: StaticAppSource): Sequence<OwnedSourceClass> {
        val path = source.path
        val text = Files.readString(path)
        val lexical = kotlinLexicalView(text)
        val packageMatch = PACKAGE.find(lexical.sanitized)
        val packageName = packageMatch?.groupValues?.get(1).orEmpty()
        require(packageName.isNotBlank()) { "owned source has no package declaration: $path" }
        val module = source.modulePath
        val sourceStem = path.fileName.toString().substringBeforeLast('.')
        if (isExcludedPackage(packageName) || sourceStem in GENERATED_NAMES) return emptySequence()
        val sources = mutableListOf<OwnedSourceClass>()
        if (path.fileName.toString().endsWith(".java")) {
            JAVA_DECLARATION.findAll(lexical.sanitized)
                .filter { match -> lexical.depths[match.range.first] == 0 }
                .map { it.groupValues[1] }
                .filterNot { isExcluded(packageName, it) }
                .mapTo(sources) { name -> OwnedSourceClass(toDescriptor("$packageName.$name"), module, path) }
        } else {
            val fileJvmName = parseFileJvmName(text, lexical, packageMatch?.range?.first ?: Int.MAX_VALUE)
            val multifileClass = parseMultifileAnnotation(lexical, packageMatch?.range?.first ?: Int.MAX_VALUE)
            val hasTopLevelJvmDeclaration = KOTLIN_JVM_DECLARATION.findAll(lexical.sanitized)
                .any { match -> lexical.depths[match.range.first] == 0 }
            val defaultFacadeName = defaultKotlinFileClassName(sourceStem)
            val facadeName = fileJvmName ?: defaultFacadeName
            val packageInternalName = packageName.replace('.', '/')
            val facadeDescriptor = toDescriptor("$packageName.$facadeName")
            val partDescriptor = if (multifileClass && fileJvmName != null) {
                toDescriptor("$packageName.${facadeName}__${defaultFacadeName}")
            } else {
                null
            }
            val sourcePart = OwnedKotlinSourcePart(
                sourceFileName = path.fileName.toString(),
                packageInternalName = packageInternalName,
                hasTopLevelJvmDeclaration = hasTopLevelJvmDeclaration,
                fileJvmName = fileJvmName,
                multifileClass = multifileClass,
                expectedFacadeDescriptor = facadeDescriptor,
                expectedPartDescriptor = partDescriptor,
            )
            KOTLIN_DECLARATION.findAll(lexical.sanitized)
                .filter { match -> lexical.depths[match.range.first] == 0 }
                .map { it.groupValues[1] }
                .filterNot { isExcluded(packageName, it) }
                .mapTo(sources) { name ->
                    OwnedSourceClass(toDescriptor("$packageName.$name"), module, path, kotlinSourcePart = sourcePart)
                }
            if (hasTopLevelJvmDeclaration) {
                when {
                    multifileClass && partDescriptor != null -> {
                        sources += OwnedSourceClass(
                            facadeDescriptor,
                            module,
                            path,
                            OwnedSourceClassKind.KOTLIN_MULTIFILE_FACADE,
                            sourcePart,
                        )
                        sources += OwnedSourceClass(
                            partDescriptor,
                            module,
                            path,
                            OwnedSourceClassKind.KOTLIN_MULTIFILE_PART,
                            sourcePart,
                        )
                    }
                    !multifileClass -> sources += OwnedSourceClass(
                        facadeDescriptor,
                        module,
                        path,
                        OwnedSourceClassKind.KOTLIN_FILE_FACADE,
                        sourcePart,
                    )
                }
            }
        }
        return sources.asSequence()
    }

    private fun isExcluded(packageName: String, name: String): Boolean =
        isExcludedPackage(packageName) || name in GENERATED_NAMES

    private fun isExcludedPackage(packageName: String): Boolean =
        ownership.generatedPackagePrefixes.any { prefix ->
            packageName == prefix || packageName.startsWith("$prefix.")
        } || ownership.excludedPackagePrefixes.any { prefix ->
            packageName == prefix || packageName.startsWith("$prefix.")
        }

    private fun withoutIncompleteMultifileGroups(sources: List<OwnedSourceClass>): List<OwnedSourceClass> {
        val completeGroups = sources.filter { it.kind == OwnedSourceClassKind.KOTLIN_MULTIFILE_PART }
            .groupBy { source -> source.module to source.kotlinSourcePart?.expectedFacadeDescriptor }
            .filterValues { parts -> parts.map(OwnedSourceClass::source).distinct().size >= 2 }
            .keys
        return sources.filter { source ->
            source.kind !in MULTIFILE_SOURCE_KINDS ||
                (source.module to source.kotlinSourcePart?.expectedFacadeDescriptor) in completeGroups
        }
    }

    private fun parseFileJvmName(text: String, lexical: KotlinLexicalView, packageStart: Int): String? {
        val matches = KOTLIN_FILE_JVM_NAME.findAll(lexical.sanitized)
            .filter { it.range.first < packageStart && lexical.depths[it.range.first] == 0 }
            .toList()
        if (matches.isEmpty()) return null
        require(matches.size == 1) { "owned Kotlin source has conflicting JvmName annotations" }
        val rawName = text.substring(matches.single().groups[1]!!.range)
        require(JVM_SIMPLE_NAME.matches(rawName)) { "owned Kotlin source has unsupported JvmName: $rawName" }
        return rawName
    }

    private fun parseMultifileAnnotation(lexical: KotlinLexicalView, packageStart: Int): Boolean {
        val matches = KOTLIN_FILE_MULTIFILE.findAll(lexical.sanitized)
            .filter { it.range.first < packageStart && lexical.depths[it.range.first] == 0 }
            .toList()
        require(matches.size <= 1) { "owned Kotlin source has duplicate JvmMultifileClass annotations" }
        return matches.isNotEmpty()
    }

    private fun defaultKotlinFileClassName(stem: String): String {
        val sanitized = stem.mapIndexed { index, character ->
            if (Character.isJavaIdentifierPart(character) && (index > 0 || Character.isJavaIdentifierStart(character))) {
                character
            } else {
                '_'
            }
        }.joinToString("")
        return sanitized.replaceFirstChar { character ->
            if (character.isLowerCase()) character.titlecase() else character.toString()
        } + "Kt"
    }

    private fun requireNoConflictingSourceDescriptors(sources: List<OwnedSourceClass>) {
        val conflicts = sources.groupBy(OwnedSourceClass::originalDescriptor)
            .filterValues { group -> group.size > 1 && !isSharedMultifileFacade(group) }
            .keys
        require(conflicts.isEmpty()) {
            "owned source inventory contains duplicate class descriptors: ${conflicts.sorted()}"
        }
    }

    private fun isSharedMultifileFacade(group: List<OwnedSourceClass>): Boolean =
        group.size >= 2 && group.all { source ->
            source.kind == OwnedSourceClassKind.KOTLIN_MULTIFILE_FACADE &&
                source.kotlinSourcePart?.hasTopLevelJvmDeclaration == true &&
                source.kotlinSourcePart.multifileClass &&
                source.kotlinSourcePart.fileJvmName != null &&
                source.kotlinSourcePart.expectedFacadeDescriptor == source.originalDescriptor
        } && group.map(OwnedSourceClass::module).distinct().size == 1 &&
            group.map(OwnedSourceClass::source).distinct().size == group.size

    /** Preserves source offsets while blanking comments and literal contents. */
    private fun kotlinLexicalView(text: String): KotlinLexicalView {
        val depths = IntArray(text.length) { -1 }
        val sanitized = CharArray(text.length) { index ->
            text[index].let { character -> if (character == '\n' || character == '\r') character else ' ' }
        }
        var braceDepth = 0
        var blockCommentDepth = 0
        var lineComment = false
        var quoted = false
        var rawQuoted = false
        var characterLiteral = false
        var backtickIdentifier = false
        var escaped = false
        var index = 0
        while (index < text.length) {
            val current = text[index]
            val next = text.getOrNull(index + 1)
            when {
                lineComment -> {
                    if (current == '\n') lineComment = false else index++
                    if (lineComment) continue
                }
                blockCommentDepth > 0 -> {
                    when {
                        current == '/' && next == '*' -> {
                            blockCommentDepth++
                            index += 2
                        }
                        current == '*' && next == '/' -> {
                            blockCommentDepth--
                            index += 2
                        }
                        else -> index++
                    }
                    continue
                }
                rawQuoted -> {
                    if (text.startsWith("\"\"\"", index)) {
                        repeat(3) { offset -> sanitized[index + offset] = '"' }
                        rawQuoted = false
                        index += 3
                    } else {
                        index++
                    }
                    continue
                }
                backtickIdentifier -> {
                    if (current == '`') {
                        sanitized[index] = current
                        backtickIdentifier = false
                    }
                    index++
                    continue
                }
                quoted || characterLiteral -> {
                    when {
                        escaped -> {
                            escaped = false
                            index++
                        }
                        current == '\\' -> {
                            escaped = true
                            index++
                        }
                        quoted && current == '"' -> {
                            sanitized[index] = current
                            quoted = false
                            index++
                        }
                        characterLiteral && current == '\'' -> {
                            sanitized[index] = current
                            characterLiteral = false
                            index++
                        }
                        else -> index++
                    }
                    continue
                }
            }

            depths[index] = braceDepth
            sanitized[index] = current
            when {
                current == '/' && next == '/' -> {
                    lineComment = true
                    index += 2
                }
                current == '/' && next == '*' -> {
                    blockCommentDepth = 1
                    index += 2
                }
                text.startsWith("\"\"\"", index) -> {
                    repeat(3) { offset ->
                        depths[index + offset] = braceDepth
                        sanitized[index + offset] = '"'
                    }
                    rawQuoted = true
                    index += 3
                }
                current == '"' -> {
                    quoted = true
                    index++
                }
                current == '\'' -> {
                    characterLiteral = true
                    index++
                }
                current == '`' -> {
                    backtickIdentifier = true
                    index++
                }
                current == '{' -> {
                    braceDepth++
                    index++
                }
                current == '}' -> {
                    braceDepth = (braceDepth - 1).coerceAtLeast(0)
                    index++
                }
                else -> index++
            }
        }
        return KotlinLexicalView(sanitized.concatToString(), depths)
    }

    private data class KotlinLexicalView(val sanitized: String, val depths: IntArray)

    private fun parseClassMappings(text: String): List<ClassMapping> {
        val mappings = mutableListOf<ClassMapping>()
        var current: MutableClassMapping? = null
        val lines = text.lineSequence().toList()
        lines.forEachIndexed { index, line ->
            val match = CLASS_MAPPING.matchEntire(line)
            if (match != null) {
                current?.freeze()?.let(mappings::add)
                val output = match.groupValues[2]
                current = if (output.startsWith("R8${'$'}${'$'}REMOVED${'$'}${'$'}")) {
                    null
                } else {
                    MutableClassMapping(toDescriptor(match.groupValues[1]), toDescriptor(output))
                }
            } else if (line.firstOrNull()?.isWhitespace() == true) {
                val mappingLeft = line.trim().substringBefore(" -> ")
                EXPLICIT_MEMBER_OWNER.find(mappingLeft)?.groupValues?.get(1)?.let { owner ->
                    val metadata = lines.getOrNull(index + 1)?.trim().orEmpty()
                    if (!R8_SYNTHESIZED_METADATA.matches(metadata)) {
                        current?.explicitMemberOwnerDescriptors?.add(toDescriptor(owner))
                    }
                }
            }
        }
        current?.freeze()?.let(mappings::add)
        return mappings
    }

    private fun owns(sourceDescriptor: String, mappedOriginal: String): Boolean =
        mappedOriginal == sourceDescriptor || mappedOriginal.startsWith(sourceDescriptor.removeSuffix(";") + "${'$'}")

    private fun resolveSources(
        mappedOriginal: String,
        sourcesByDescriptor: Map<String, List<OwnedSourceClass>>,
    ): Set<OwnedSourceClass>? {
        sourcesByDescriptor[mappedOriginal]?.let { return it.toSet() }
        val candidates = sourcesByDescriptor.keys.filter { descriptor -> owns(descriptor, mappedOriginal) }
        val longest = candidates.maxOfOrNull(String::length) ?: return null
        val descriptor = candidates.singleOrNull { it.length == longest } ?: return null
        return sourcesByDescriptor.getValue(descriptor).toSet()
    }

    private fun toDescriptor(fqcn: String): String = "L${fqcn.replace('.', '/')};"

    private data class ClassMapping(
        val originalDescriptor: String,
        val outputDescriptor: String,
        val explicitMemberOwnerDescriptors: Set<String>,
    )

    private data class MutableClassMapping(
        val originalDescriptor: String,
        val outputDescriptor: String,
        val explicitMemberOwnerDescriptors: MutableSet<String> = linkedSetOf(),
    ) {
        fun freeze() = ClassMapping(originalDescriptor, outputDescriptor, explicitMemberOwnerDescriptors.toSet())
    }

    companion object {
        private val GENERATED_NAMES = setOf("R", "BR", "BuildConfig", "MyObjectBox")
        private val EXCLUDED_PATH_COMPONENTS = setOf("build", "generated", "test", "androidtest", "testfixtures")
        private val PACKAGE = Regex("(?m)^\\s*package\\s+([A-Za-z_][A-Za-z0-9_.]*)\\s*;?")
        private val KOTLIN_DECLARATION = Regex(
            "(?m)^[^\\S\\r\\n]*(?:(?:public|internal|private|protected|data|sealed|open|abstract|value|inline|fun)\\s+)*" +
                "(?:enum\\s+class|annotation\\s+class|class|object|interface)\\s+([A-Za-z_][A-Za-z0-9_]*)",
        )
        private val KOTLIN_JVM_DECLARATION = Regex(
            "(?m)^[^\\S\\r\\n]*(?:(?:public|internal|private|protected|inline|suspend|operator|infix|tailrec|external|const|lateinit)\\s+)*" +
                "(?:fun(?!\\s+interface\\b)|val|var)\\s+",
        )
        private val KOTLIN_FILE_JVM_NAME = Regex(
            "@file:\\s*(?:kotlin\\.jvm\\.)?JvmName\\s*\\(\\s*\\\"([^\\\"]*)\\\"\\s*\\)",
        )
        private val KOTLIN_FILE_MULTIFILE = Regex("@file:\\s*(?:kotlin\\.jvm\\.)?JvmMultifileClass\\b")
        private val JVM_SIMPLE_NAME = Regex("[A-Za-z_${'$'}][A-Za-z0-9_${'$'}]*")
        private val MULTIFILE_SOURCE_KINDS = setOf(
            OwnedSourceClassKind.KOTLIN_MULTIFILE_FACADE,
            OwnedSourceClassKind.KOTLIN_MULTIFILE_PART,
        )
        private val JAVA_DECLARATION = Regex(
            "\\b(?:class|interface|enum|record)\\s+([A-Za-z_${'$'}][A-Za-z0-9_${'$'}]*)",
        )
        private val CLASS_MAPPING = Regex("^([^#\\s].*?) -> ([^\\s]+):$")
        private val EXPLICIT_MEMBER_OWNER = Regex(
            "(?:^|:)[^\\s:]+\\s+([A-Za-z_${'$'}][A-Za-z0-9_${'$'}]*(?:\\.[A-Za-z_${'$'}][A-Za-z0-9_${'$'}]*)+)" +
                "\\.[A-Za-z_${'$'}<][A-Za-z0-9_${'$'}<>]*\\s*(?:\\(|(?:$|:))",
        )
        private val R8_SYNTHESIZED_METADATA = Regex(
            "^#\\s*\\{\\s*\"id\"\\s*:\\s*\"com\\.android\\.tools\\.r8\\.synthesized\"\\s*}$",
        )
    }
}

/** Produces the closed app-only subset accepted by R8's public `-applymapping` input. */
class AppOnlyMappingFilter(
    repositoryRoot: Path,
    ownership: HardeningOwnership,
) {
    private val inventory = OwnedDexInventoryBuilder(repositoryRoot, ownership)

    fun filter(mappingText: String): String {
        if (mappingText.isBlank()) return ""
        val owned = inventory.sourceInventory().mapTo(linkedSetOf()) { it.originalDescriptor }
        val acceptedOutputs = inventory.build(mappingText).acceptedDexDescriptors
        val output = mutableListOf<String>()
        var keepClass = false
        mappingText.lineSequence().forEach { line ->
            val header = CLASS_HEADER.matchEntire(line)
            when {
                header != null -> {
                    val original = toDescriptor(header.groupValues[1])
                    keepClass = owned.any { source ->
                        original == source || original.startsWith(source.removeSuffix(";") + "${'$'}")
                    } && toDescriptor(header.groupValues[2]) in acceptedOutputs
                    if (keepClass) output += line
                }
                line.firstOrNull()?.isWhitespace() == true -> if (keepClass) output += line
                line.isBlank() -> Unit
                line.startsWith('#') -> Unit
                else -> throw IllegalArgumentException("previous R8 mapping contains an unsupported top-level line")
            }
        }
        if (output.none { CLASS_HEADER.matches(it) }) return ""
        return output.joinToString("\n", postfix = "\n")
    }

    private fun toDescriptor(fqcn: String): String = "L${fqcn.replace('.', '/')};"

    private companion object {
        val CLASS_HEADER = Regex("^([^#\\s].*?) -> ([^\\s]+):$")
    }
}
