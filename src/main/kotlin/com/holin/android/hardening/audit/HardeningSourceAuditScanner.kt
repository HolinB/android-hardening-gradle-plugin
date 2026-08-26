package com.holin.android.hardening.audit

import com.holin.android.hardening.HardeningOwnership
import com.holin.android.hardening.HardcodedReferenceKind
import com.holin.android.hardening.inventory.AppSourceKind
import com.holin.android.hardening.inventory.AppSourceInventory
import com.holin.android.hardening.inventory.AppStaticResourceDirectoryPolicy
import com.holin.android.hardening.inventory.GitIgnoreMatcher
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.Locale
import javax.xml.parsers.SAXParserFactory
import org.xml.sax.Attributes
import org.xml.sax.InputSource
import org.xml.sax.Locator
import org.xml.sax.helpers.DefaultHandler

enum class ResolvedContractKind { CLASS_FOR_NAME, CLASS_LOADER, METHOD, FIELD, RESOURCE_IDENTIFIER }
enum class UnresolvedContractKind { APP_REFLECTION, RESOURCE_LOOKUP, GSON_FIELD_NAMING_STRATEGY }
enum class ExternalNameContractKind {
    GSON_UNEXPLICIT_FIELD,
    SERIALIZABLE,
    OBJECTBOX_ENTITY,
    JAVASCRIPT_INTERFACE,
    JNI_NATIVE,
    EXPORTED_COMPONENT,
    MANIFEST_DECLARED_CLASS,
    LAYOUT_CUSTOM_VIEW,
    GENERATED_VIEW_BINDING_REFLECTION,
    PLATFORM_REFLECTION,
    PLATFORM_RESOURCE_LOOKUP,
}
enum class ExternalNameAction { PRESERVE_AND_REPORT }

data class ResolvedContract(
    val kind: ResolvedContractKind,
    val sourceFile: String,
    val line: Int,
    val resolvedName: String,
    val expression: String,
    val ownerInternalName: String? = null,
    val jvmDescriptor: String? = null,
)

data class UnresolvedContract(
    val kind: UnresolvedContractKind,
    val sourceFile: String,
    val line: Int,
    val expression: String,
    val reason: String,
)

data class ExternalNameCandidate(
    val kind: ExternalNameContractKind,
    val sourceFile: String,
    val line: Int,
    val symbol: String,
    val action: ExternalNameAction = ExternalNameAction.PRESERVE_AND_REPORT,
)

data class HardcodedReferenceFinding(
    val kind: HardcodedReferenceKind,
    val sourceFile: String,
    val line: Int,
    val value: String,
    val ownerInternalName: String? = null,
    val jvmDescriptor: String? = null,
)

data class UnresolvedHardcodedReference(
    val kind: HardcodedReferenceKind,
    val sourceFile: String,
    val line: Int,
    val expression: String,
    val reason: String,
)

data class HardeningSourceAudit(
    val productionSourceFiles: List<String>,
    val resolvedContracts: List<ResolvedContract>,
    val unresolvedContracts: List<UnresolvedContract>,
    val externalNameCandidates: List<ExternalNameCandidate>,
    val webpDiversificationFiles: List<String> = emptyList(),
    val hardcodedReferenceSourceFiles: List<String> = emptyList(),
    val hardcodedReferenceFindings: List<HardcodedReferenceFinding> = emptyList(),
    val unresolvedHardcodedReferences: List<UnresolvedHardcodedReference> = emptyList(),
)

/** Conservative source audit. It never rewrites source and rejects syntax it cannot prove static. */
class HardeningSourceAuditScanner(
    repositoryRoot: Path,
    appDirectory: Path,
    private val namespace: String,
    private val appStaticResourceLayers: List<List<Path>>? = null,
    private val ownership: HardeningOwnership,
) {
    private val root = repositoryRoot.toAbsolutePath().normalize()
    private val app = appDirectory.toAbsolutePath().normalize()
    private val appStaticResourceDirectoryPolicy = AppStaticResourceDirectoryPolicy(root, app)
    private val gitIgnoreMatcher = GitIgnoreMatcher(root)

    fun scan(): HardeningSourceAudit {
        val ownedSources = collectOwnedSources(ownership)
        val sources = ownedSources
            .filterNot { source ->
                appStaticResourceLayers != null && source.path.startsWith(app) && source.kind == AppSourceKind.RESOURCE
            }
            .distinctBy { source -> source.path.toAbsolutePath().normalize() }
        val selectedAppResources = appStaticResourceLayers?.let(::selectedAppResources).orEmpty()
        val hardcodedReferenceSources = collectHardcodedReferenceSources(ownedSources)
        val resolved = mutableListOf<ResolvedContract>()
        val unresolved = mutableListOf<UnresolvedContract>()
        val external = mutableListOf<ExternalNameCandidate>()
        sources.forEach { source ->
            val relative = portable(root.relativize(source.path.toAbsolutePath().normalize()))
            when (source.kind) {
                AppSourceKind.JAVA, AppSourceKind.KOTLIN -> {
                    val text = Files.readString(source.path)
                    scanCode(relative, text, resolved, unresolved, external)
                }
                AppSourceKind.MANIFEST -> scanManifest(relative, source.path, external)
                AppSourceKind.RESOURCE -> scanLayout(relative, source.logicalName, source.path, external)
            }
        }
        selectedAppResources.forEach { source ->
            scanLayout(source.relativePath, source.logicalName, source.path, external)
        }
        val hardcodedReferenceFindings = hardcodedReferenceFindings(
            hardcodedReferenceSources,
            resolved,
        )
        val unresolvedHardcodedReferences = unresolvedHardcodedReferences(
            hardcodedReferenceSources,
            unresolved,
        )
        return HardeningSourceAudit(
            (
                sources.map { portable(root.relativize(it.path.toAbsolutePath().normalize())) } +
                    selectedAppResources.map(SelectedAppResource::relativePath)
                ).sorted(),
            resolved.sortedWith(compareBy({ it.sourceFile }, { it.line }, { it.kind.name }, { it.resolvedName })),
            unresolved.sortedWith(compareBy({ it.sourceFile }, { it.line }, { it.kind.name }, { it.expression })),
            external.distinct().sortedWith(compareBy({ it.sourceFile }, { it.line }, { it.kind.name }, { it.symbol })),
            ownedSources.asSequence()
                .filter { it.kind == AppSourceKind.RESOURCE && it.path.fileName.toString().endsWith(".webp", true) }
                .filter { source ->
                    val module = requireNotNull(moduleFor(source))
                    ownership.isWebpIncluded(
                        module.path,
                        portable(module.directory.relativize(source.path.toAbsolutePath().normalize())),
                    )
                }
                .map { portable(root.relativize(it.path.toAbsolutePath().normalize())) }
                .sorted()
                .toList(),
            hardcodedReferenceSources.map { source ->
                portable(root.relativize(source.path.toAbsolutePath().normalize()))
            },
            hardcodedReferenceFindings,
            unresolvedHardcodedReferences,
        )
    }

    private fun unresolvedHardcodedReferences(
        sources: List<AuditSource>,
        unresolvedContracts: List<UnresolvedContract>,
    ): List<UnresolvedHardcodedReference> {
        val sourcePaths = sources.mapTo(hashSetOf()) { source ->
            portable(root.relativize(source.path.toAbsolutePath().normalize()))
        }
        return unresolvedContracts.mapNotNull { contract ->
            val kind = unresolvedHardcodedKind(contract) ?: return@mapNotNull null
            if (contract.sourceFile !in sourcePaths || kind !in ownership.hardcodedReferences.kinds) {
                null
            } else {
                UnresolvedHardcodedReference(
                    kind,
                    contract.sourceFile,
                    contract.line,
                    contract.expression,
                    contract.reason,
                )
            }
        }.distinct().sortedWith(compareBy({ it.sourceFile }, { it.line }, { it.kind.name }, { it.expression }))
    }

    private fun unresolvedHardcodedKind(contract: UnresolvedContract): HardcodedReferenceKind? = when (contract.kind) {
        UnresolvedContractKind.RESOURCE_LOOKUP -> HardcodedReferenceKind.RESOURCE_NAME
        UnresolvedContractKind.APP_REFLECTION -> if (
            contract.expression.contains(".getMethod(") ||
            contract.expression.contains(".getDeclaredMethod(") ||
            contract.expression.contains(".getField(") ||
            contract.expression.contains(".getDeclaredField(")
        ) {
            HardcodedReferenceKind.MEMBER_NAME
        } else {
            HardcodedReferenceKind.CLASS_NAME
        }
        UnresolvedContractKind.GSON_FIELD_NAMING_STRATEGY -> null
    }

    private fun hardcodedReferenceFindings(
        sources: List<AuditSource>,
        resolvedContracts: List<ResolvedContract>,
    ): List<HardcodedReferenceFinding> {
        val sourcePaths = sources.mapTo(hashSetOf()) { source ->
            portable(root.relativize(source.path.toAbsolutePath().normalize()))
        }
        val findings = resolvedContracts.mapNotNull { contract ->
            val kind = when (contract.kind) {
                ResolvedContractKind.CLASS_FOR_NAME,
                ResolvedContractKind.CLASS_LOADER,
                -> HardcodedReferenceKind.CLASS_NAME
                ResolvedContractKind.METHOD,
                ResolvedContractKind.FIELD,
                -> HardcodedReferenceKind.MEMBER_NAME
                ResolvedContractKind.RESOURCE_IDENTIFIER -> HardcodedReferenceKind.RESOURCE_NAME
            }
            if (contract.sourceFile !in sourcePaths || kind !in ownership.hardcodedReferences.kinds) {
                null
            } else {
                HardcodedReferenceFinding(
                    kind,
                    contract.sourceFile,
                    contract.line,
                    contract.resolvedName,
                    contract.ownerInternalName,
                    contract.jvmDescriptor,
                )
            }
        }.toMutableList()
        sources.forEach { source ->
            val relative = portable(root.relativize(source.path.toAbsolutePath().normalize()))
            findings += literalFindings(relative, Files.readString(source.path))
        }
        return findings.distinct().sortedWith(compareBy({ it.sourceFile }, { it.line }, { it.kind.name }, { it.value }))
    }

    private fun literalFindings(relative: String, source: String): List<HardcodedReferenceFinding> {
        val searchable = if (relative.endsWith(".xml", true)) maskXmlComments(source) else mask(source).cleaned
        return STRING_LITERAL.findAll(searchable).mapNotNull { match ->
            val value = match.groupValues[1]
            val kind = literalKind(value) ?: return@mapNotNull null
            if (kind !in ownership.hardcodedReferences.kinds) return@mapNotNull null
            HardcodedReferenceFinding(kind, relative, line(source, match.range.first), value)
        }.toList()
    }

    private fun maskXmlComments(source: String): String {
        val masked = source.toCharArray()
        var start = source.indexOf("<!--")
        while (start >= 0) {
            val closing = source.indexOf("-->", start + 4)
            val end = if (closing < 0) source.length else closing + 3
            blank(masked, start, end - start)
            start = source.indexOf("<!--", end)
        }
        return String(masked)
    }

    private fun literalKind(value: String): HardcodedReferenceKind? = when {
        value.contains("schemas.android.com/") -> null
        URL_LITERAL.matches(value) -> HardcodedReferenceKind.URL
        URI_LITERAL.matches(value) -> HardcodedReferenceKind.URI
        ROUTE_LITERAL.matches(value) -> HardcodedReferenceKind.ROUTE
        FILE_NAME_LITERAL.matches(value) -> HardcodedReferenceKind.FILE_NAME
        else -> null
    }

    private fun collectHardcodedReferenceSources(sources: List<AuditSource>): List<AuditSource> {
        val eligible = sources.asSequence()
            .filter { source ->
                source.kind == AppSourceKind.JAVA || source.kind == AppSourceKind.KOTLIN ||
                    (source.path.fileName.toString().endsWith(".xml", true) &&
                        (source.kind == AppSourceKind.MANIFEST || source.kind == AppSourceKind.RESOURCE))
            }
            .filter { source ->
                val module = requireNotNull(moduleFor(source))
                ownership.hardcodedReferences.includes(
                    portable(module.directory.relativize(source.path.toAbsolutePath().normalize())),
                )
            }
            .sortedWith(compareBy { source -> portable(root.relativize(source.path.toAbsolutePath().normalize())) })
            .toList()
        ownership.requireMatchedHardcodedReferenceIncludes(
            eligible.groupBy { source -> requireNotNull(moduleFor(source)).path }
                .mapValues { (_, moduleSources) ->
                    moduleSources.mapTo(linkedSetOf()) { source ->
                        val module = requireNotNull(moduleFor(source))
                        portable(module.directory.relativize(source.path.toAbsolutePath().normalize()))
                    }
                },
        )
        return eligible
    }

    private fun collectOwnedSources(ownership: HardeningOwnership): List<AuditSource> {
        ownership.modules.forEach { module ->
            (
                module.sourceRoots.javaDirectories + module.sourceRoots.kotlinDirectories +
                    module.sourceRoots.resourceDirectories + module.sourceRoots.manifestFiles
                ).forEach sourcePathLoop@{ sourcePath ->
                requireNoSymlinks(sourcePath)
                if (Files.isDirectory(sourcePath, NOFOLLOW_LINKS)) {
                    Files.walk(sourcePath).use { paths -> paths.forEach(::requireNoSymlinks) }
                }
            }
        }
        val selected = AppSourceInventory(root, ownership, gitIgnoreMatcher).scan().asSequence()
            .map { source -> AuditSource(source.path, source.modulePath, source.kind, source.logicalName) }
            .filterNot(::isExcludedPackage)
            .sortedWith(compareBy(AuditSource::kind, AuditSource::logicalName, { it.path.toString() }))
            .toList()
        ownership.requireMatchedWebpIncludes(
            selected.asSequence()
                .filter { it.kind == AppSourceKind.RESOURCE && it.path.fileName.toString().endsWith(".webp", true) }
                .groupBy { source -> requireNotNull(moduleFor(source)).path }
                .mapValues { (_, sources) ->
                    sources.mapTo(linkedSetOf()) { source ->
                        val module = requireNotNull(moduleFor(source))
                        portable(module.directory.relativize(source.path.toAbsolutePath().normalize()))
                    }
                },
        )
        return selected
    }

    private fun moduleFor(source: AuditSource): HardeningOwnership.OwnedModule? =
        ownership.modules.singleOrNull { it.path == source.modulePath }

    private fun isExcludedPackage(source: AuditSource): Boolean {
        if (source.kind != AppSourceKind.JAVA && source.kind != AppSourceKind.KOTLIN) return false
        val packageName = PACKAGE_DECLARATION.find(Files.readString(source.path))?.groupValues?.get(1) ?: return false
        return (ownership.generatedPackagePrefixes + ownership.excludedPackagePrefixes).any { prefix ->
            packageName == prefix || packageName.startsWith("$prefix.")
        }
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

    private data class AuditSource(
        val path: Path,
        val modulePath: String,
        val kind: AppSourceKind,
        val logicalName: String,
    )

    private fun selectedAppResources(layers: List<List<Path>>): List<SelectedAppResource> {
        val candidates = layers.flatMapIndexed { layerIndex, directories ->
            directories.flatMap { directory -> collectLayerResources(directory, layerIndex) }
        }
        val ignored = gitIgnoreMatcher.ignored(candidates.map(SelectedAppResource::path))
        return candidates.filterNot { it.path in ignored }
            .groupBy { it.logicalName.lowercase(Locale.ROOT) }
            .values
            .map { candidatesForName ->
                val winnerLayer = candidatesForName.minOf(SelectedAppResource::layer)
                val winners = candidatesForName.filter { it.layer == winnerLayer }
                require(winners.size == 1) {
                    "ambiguous static app resource winner for ${candidatesForName.first().logicalName} " +
                        "at layer $winnerLayer: ${winners.map(SelectedAppResource::path).sorted().joinToString()}"
                }
                winners.single()
            }
            .sortedWith(compareBy(SelectedAppResource::logicalName, SelectedAppResource::relativePath))
    }

    private fun collectLayerResources(directory: Path, layer: Int): List<SelectedAppResource> {
        val normalized = directory.toAbsolutePath().normalize()
        if (!isAcceptedResourceDirectory(normalized)) return emptyList()
        return buildList {
            Files.walk(normalized).use { paths ->
                paths.filter { path ->
                    Files.isRegularFile(path, NOFOLLOW_LINKS) &&
                        !containsExcludedComponent(normalized.relativize(path))
                }.forEach { path ->
                    add(
                        SelectedAppResource(
                            path = path.toAbsolutePath().normalize(),
                            relativePath = portable(root.relativize(path.toAbsolutePath().normalize())),
                            logicalName = portable(normalized.relativize(path)),
                            layer = layer,
                        ),
                    )
                }
            }
        }
    }

    private fun isAcceptedResourceDirectory(directory: Path): Boolean =
        appStaticResourceDirectoryPolicy.accepts(directory)

    private fun containsExcludedComponent(path: Path): Boolean = path.iterator().asSequence()
        .map { component -> component.toString().lowercase(Locale.ROOT) }
        .any(EXCLUDED_RESOURCE_COMPONENTS::contains)

    private fun scanCode(
        relative: String,
        source: String,
        resolved: MutableList<ResolvedContract>,
        unresolved: MutableList<UnresolvedContract>,
        external: MutableList<ExternalNameCandidate>,
    ) {
        val lexical = mask(source)
        val constants = stringConstants(lexical.cleaned)
        val imports = importedTypes(lexical.cleaned)
        val packageName = PACKAGE_DECLARATION.find(lexical.cleaned)?.groupValues?.get(1).orEmpty()
        CALLS.flatMap { pattern -> pattern.regex.findAll(lexical.mask).map { pattern to it }.toList() }
            .sortedBy { it.second.range.first }
            .forEach { (pattern, match) ->
                val open = lexical.mask.indexOf('(', match.range.first)
                val close = matchingParen(lexical.cleaned, open)
                if (close < 0) {
                    unresolved += UnresolvedContract(
                        pattern.unresolvedKind,
                        relative,
                        line(source, match.range.first),
                        source.substring(match.range.first).lineSequence().first().trim(),
                        "unterminated invocation",
                    )
                    return@forEach
                }
                val expression = source.substring(match.range.first, close + 1).trim()
                val arguments = splitArguments(lexical.cleaned.substring(open + 1, close))
                val values = arguments.map { evaluateString(it, constants) }
                val failure = when (pattern.kind) {
                    ResolvedContractKind.CLASS_FOR_NAME,
                    ResolvedContractKind.CLASS_LOADER,
                    -> classResolution(values.singleOrNull())
                    ResolvedContractKind.METHOD -> methodResolution(
                        source,
                        match.range.first,
                        arguments,
                        values,
                        imports,
                        packageName,
                    )
                    ResolvedContractKind.FIELD -> memberResolution(
                        source,
                        match.range.first,
                        values.firstOrNull(),
                        imports,
                        packageName,
                    )
                    ResolvedContractKind.RESOURCE_IDENTIFIER -> resourceResolution(values)
                }
                if (failure == null) {
                    val externalKind = externalContractKind(
                        pattern.kind,
                        source,
                        lexical.cleaned,
                        match.range.first,
                        arguments,
                        values,
                        imports,
                    )
                    if (externalKind == null) {
                        unresolved += UnresolvedContract(
                            pattern.unresolvedKind,
                            relative,
                            line(source, match.range.first),
                            expression,
                            "arguments, receiver, or JVM descriptor are not compile-time constants",
                        )
                    } else {
                        external += candidate(externalKind, relative, source, match.range.first, expression)
                    }
                } else {
                    resolved += ResolvedContract(
                        pattern.kind,
                        relative,
                        line(source, match.range.first),
                        failure.value,
                        expression,
                        failure.ownerInternalName,
                        failure.jvmDescriptor,
                    )
                }
            }
        scanExternalContracts(relative, source, lexical.cleaned, external)
        scanGsonFieldNaming(relative, source, lexical, unresolved)
    }

    private fun scanGsonFieldNaming(
        relative: String,
        original: String,
        lexical: LexicalSource,
        unresolved: MutableList<UnresolvedContract>,
    ) {
        GSON_FIELD_NAMING_STRATEGY.findAll(lexical.mask).forEach { call ->
            val open = lexical.mask.indexOf('(', call.range.first)
            val close = matchingParen(lexical.cleaned, open)
            val argument = if (close > open) {
                splitArguments(lexical.cleaned.substring(open + 1, close)).singleOrNull()?.trim()
            } else {
                null
            }
            if (argument != null && BUILT_IN_FIELD_NAMING_POLICY.matches(argument.replace(" ", ""))) {
                return@forEach
            }
            val end = if (close > open) {
                close + 1
            } else {
                original.indexOf('\n', call.range.first).let { if (it < 0) original.length else it }
            }
            unresolved += UnresolvedContract(
                UnresolvedContractKind.GSON_FIELD_NAMING_STRATEGY,
                relative,
                line(original, call.range.first),
                original.substring(call.range.first, end).trim(),
                "custom Gson FieldNamingStrategy can derive JSON keys from renamed metadata",
            )
        }
    }

    private fun methodResolution(
        source: String,
        callStart: Int,
        arguments: List<String>,
        values: List<String?>,
        imports: Map<String, String>,
        packageName: String,
    ): Resolution? {
        val receiver = receiverType(source, callStart)?.let(::classLiteral) ?: return null
        val owner = internalName(receiver, imports, packageName) ?: return null
        val parameters = arguments.drop(1).map { classLiteral(it) ?: return null }
        val parameterDescriptors = parameters.map { parameter ->
            descriptor(parameter, imports, packageName) ?: return null
        }
        val parameterDescriptor = parameterDescriptors.joinToString("", "(", ")")
        return Resolution("${values.firstOrNull() ?: return null}(${parameters.joinToString()})", owner, parameterDescriptor)
    }

    private fun memberResolution(
        source: String,
        callStart: Int,
        name: String?,
        imports: Map<String, String>,
        packageName: String,
    ): Resolution? {
        val receiver = receiverType(source, callStart)?.let(::classLiteral) ?: return null
        val owner = internalName(receiver, imports, packageName) ?: return null
        return name?.let { Resolution(it, owner, null) }
    }

    private fun classResolution(name: String?): Resolution? {
        val binaryName = name?.takeIf(FULLY_QUALIFIED_CLASS::matches) ?: return null
        val owner = binaryName.replace('.', '/')
        return Resolution(binaryName, owner, "L$owner;")
    }

    private fun internalName(type: String, imports: Map<String, String>, packageName: String): String? {
        val resolved = sourceType(type, imports, packageName) ?: return null
        if (resolved in JVM_PRIMITIVE_DESCRIPTORS) return null
        return resolved.replace('.', '/')
    }

    private fun descriptor(type: String, imports: Map<String, String>, packageName: String): String? {
        val resolved = sourceType(type, imports, packageName) ?: return null
        return JVM_PRIMITIVE_DESCRIPTORS[resolved] ?: "L${resolved.replace('.', '/')};"
    }

    private fun sourceType(type: String, imports: Map<String, String>, packageName: String): String? {
        val normalized = type.trim()
        if (normalized in JVM_PRIMITIVE_DESCRIPTORS) return normalized
        if (normalized.startsWith("java.") || normalized.startsWith("javax.") || normalized.startsWith("android.")) {
            return normalized
        }
        imports[normalized]?.let { return it }
        if ('.' in normalized) return normalized.takeIf(FULLY_QUALIFIED_CLASS::matches)
        return packageName.takeIf(String::isNotBlank)?.let { "$it.$normalized" }
    }

    private fun resourceResolution(values: List<String?>): Resolution? {
        if (values.size != 3 || values.any { it == null }) return null
        return Resolution("${values[2]}:${values[1]}/${values[0]}")
    }

    private fun externalContractKind(
        kind: ResolvedContractKind,
        source: String,
        cleaned: String,
        callStart: Int,
        arguments: List<String>,
        values: List<String?>,
        imports: Map<String, String>,
    ): ExternalNameContractKind? {
        if (kind == ResolvedContractKind.RESOURCE_IDENTIFIER && values.getOrNull(2) == "android") {
            return ExternalNameContractKind.PLATFORM_RESOURCE_LOOKUP
        }
        if (kind == ResolvedContractKind.CLASS_FOR_NAME &&
            arguments.singleOrNull()?.let { isPlatformClassExpression(it, imports) } == true
        ) {
            return ExternalNameContractKind.PLATFORM_REFLECTION
        }
        if (kind != ResolvedContractKind.METHOD && kind != ResolvedContractKind.FIELD) return null

        val receiver = receiverIdentifier(source, callStart) ?: return null
        if (kind == ResolvedContractKind.METHOD && values.firstOrNull() == "inflate" &&
            isViewBindingReceiver(cleaned, receiver)
        ) {
            return ExternalNameContractKind.GENERATED_VIEW_BINDING_REFLECTION
        }
        val directType = receiverType(source, callStart)?.let { classLiteral(it) ?: it }
        if (directType != null && isPlatformType(directType, imports)) {
            return ExternalNameContractKind.PLATFORM_REFLECTION
        }
        if (receiver in platformClassVariables(cleaned, imports)) {
            return ExternalNameContractKind.PLATFORM_REFLECTION
        }
        if (kind == ResolvedContractKind.FIELD && receiver == "superClass" &&
            ANDROID_FIELD_HELPER_CLASS.containsMatchIn(cleaned) &&
            ANDROID_FIELD_HELPER_RECEIVER.containsMatchIn(cleaned)
        ) {
            return ExternalNameContractKind.PLATFORM_REFLECTION
        }
        return null
    }

    private fun importedTypes(source: String): Map<String, String> = IMPORT.findAll(source)
        .map { match -> match.groupValues[1].substringAfterLast('.') to match.groupValues[1] }
        .toMap()

    private fun receiverIdentifier(source: String, callStart: Int): String? =
        IDENTIFIER_RECEIVER.find(source.substring(0, callStart))?.groupValues?.get(1)

    private fun isViewBindingReceiver(source: String, receiver: String): Boolean = Regex(
        "(?:ViewBinding::class\\.java|ViewBinding\\.class)\\.isAssignableFrom\\(\\s*" +
            Regex.escape(receiver) + "\\s*\\)",
    ).containsMatchIn(source)

    private fun platformClassVariables(source: String, imports: Map<String, String>): Set<String> = buildSet {
        CLASS_FOR_NAME_ASSIGNMENT.findAll(source).forEach { match ->
            if (isPlatformClassExpression(match.groupValues[2], imports)) add(match.groupValues[1])
        }
        JAVA_BOUNDED_CLASS_ASSIGNMENT.findAll(source).forEach { match ->
            if (isPlatformType(match.groupValues[1], imports)) add(match.groupValues[2])
        }
    }

    private fun isPlatformClassExpression(expression: String, imports: Map<String, String>): Boolean {
        val value = decodeLiteralPreservingDollar(expression)
            ?: KOTLIN_CLASS_NAME.matchEntire(expression.trim())?.groupValues?.get(1)?.let { resolveType(it, imports) }
            ?: JAVA_CLASS_NAME.matchEntire(expression.trim())?.groupValues?.get(1)?.let { resolveType(it, imports) }
            ?: return false
        return isPlatformName(value)
    }

    private fun decodeLiteralPreservingDollar(expression: String): String? {
        val value = stripParentheses(expression.trim())
        if (value.length < 2 || value.first() != value.last() || value.first() !in setOf('\'', '"')) return null
        return decodeEscapes(value.substring(1, value.lastIndex))
    }

    private fun isPlatformType(type: String, imports: Map<String, String>): Boolean =
        isPlatformName(resolveType(type.substringBefore("::").substringBefore(".class"), imports))

    private fun resolveType(type: String, imports: Map<String, String>): String {
        val normalized = type.trim()
        return imports[normalized.substringAfterLast('.')] ?: normalized
    }

    private fun isPlatformName(value: String): Boolean =
        value.startsWith("android.") || value.startsWith("java.") || value.startsWith("javax.")

    private fun receiverType(source: String, callStart: Int): String? {
        val prefix = source.substring(0, callStart)
        val match = CLASS_RECEIVER.find(prefix) ?: return null
        return match.groupValues[1]
    }

    private fun classLiteral(value: String): String? {
        val trimmed = value.trim()
        JAVA_CLASS_LITERAL.matchEntire(trimmed)?.let { return normalizeType(it.groupValues[1], primitive = false) }
        KOTLIN_CLASS_LITERAL.matchEntire(trimmed)?.let {
            return normalizeType(it.groupValues[1], primitive = it.groupValues[2] == "PrimitiveType")
        }
        return null
    }

    private fun normalizeType(type: String, primitive: Boolean): String {
        val simple = type.substringAfterLast('.')
        if (primitive) return KOTLIN_PRIMITIVES[simple] ?: type
        return KOTLIN_TYPES[simple] ?: type
    }

    private fun scanExternalContracts(
        relative: String,
        original: String,
        cleaned: String,
        output: MutableList<ExternalNameCandidate>,
    ) {
        if (SERIALIZABLE.containsMatchIn(cleaned)) {
            classDeclarations(cleaned).forEach { (name, offset) ->
                output += candidate(ExternalNameContractKind.SERIALIZABLE, relative, original, offset, name)
            }
        }
        ENTITY.findAll(cleaned).forEach { annotation ->
            nextClass(cleaned, annotation.range.last + 1)?.let { (name, offset) ->
                output += candidate(ExternalNameContractKind.OBJECTBOX_ENTITY, relative, original, offset, name)
            }
        }
        JAVASCRIPT.findAll(cleaned).forEach { annotation ->
            nextFunction(cleaned, annotation.range.last + 1)?.let { (name, offset) ->
                output += candidate(ExternalNameContractKind.JAVASCRIPT_INTERFACE, relative, original, offset, name)
            }
        }
        NATIVE_FUNCTION.findAll(cleaned).forEach { match ->
            val name = match.groupValues.drop(1).firstOrNull(String::isNotBlank) ?: return@forEach
            output += candidate(ExternalNameContractKind.JNI_NATIVE, relative, original, match.range.first, name)
        }
        if (isModelLike(relative, cleaned)) {
            PROPERTY.findAll(cleaned).forEach { property ->
                val prefixStart = maxOf(0, previousDelimiter(cleaned, property.range.first))
                val prefix = cleaned.substring(prefixStart, property.range.first)
                if (!SERIALIZED_NAME.containsMatchIn(prefix)) {
                    output += candidate(
                        ExternalNameContractKind.GSON_UNEXPLICIT_FIELD,
                        relative,
                        original,
                        property.range.first,
                        property.groupValues[1],
                    )
                }
            }
        }
    }

    private fun scanManifest(relative: String, path: Path, output: MutableList<ExternalNameCandidate>) {
        var manifestPackage = namespace
        val declarations = mutableListOf<ManifestClassDeclaration>()
        scanXml(path, object : DefaultHandler() {
            private var locator: Locator? = null

            override fun setDocumentLocator(locator: Locator) {
                this.locator = locator
            }

            override fun startElement(uri: String, localName: String, qName: String, attributes: Attributes) {
                val tag = localName.ifBlank { qName }
                if (tag == "manifest") {
                    attributes.getValue("package")?.trim()?.takeIf(String::isNotBlank)?.let { manifestPackage = it }
                    return
                }
                val attribute = when (tag) {
                    "activity-alias" -> "targetActivity"
                    "application", "activity", "service", "receiver", "provider", "instrumentation" -> "name"
                    else -> return
                }
                val name = attributes.getValue(ANDROID_NS, attribute)?.trim().orEmpty()
                if (name.isBlank()) return
                val line = locator?.lineNumber ?: 1
                declarations += ManifestClassDeclaration(name, line)
                if (tag in EXPORTED_COMPONENT_TAGS && attributes.getValue(ANDROID_NS, "exported") == "true") {
                    output += ExternalNameCandidate(
                        ExternalNameContractKind.EXPORTED_COMPONENT,
                        relative,
                        line,
                        resolveManifestName(name, manifestPackage),
                    )
                }
            }
        })
        declarations.forEach { declaration ->
            output += ExternalNameCandidate(
                ExternalNameContractKind.MANIFEST_DECLARED_CLASS,
                relative,
                declaration.line,
                resolveManifestName(declaration.name, manifestPackage),
            )
        }
    }

    private fun scanLayout(relative: String, logicalName: String, path: Path, output: MutableList<ExternalNameCandidate>) {
        val directory = logicalName.substringBefore('/')
        if ((directory != "layout" && !directory.startsWith("layout-")) || !logicalName.endsWith(".xml")) return
        scanXml(path, object : DefaultHandler() {
            private var locator: Locator? = null

            override fun setDocumentLocator(locator: Locator) {
                this.locator = locator
            }

            override fun startElement(uri: String, localName: String, qName: String, attributes: Attributes) {
                val tag = localName.ifBlank { qName }
                val symbol = when {
                    isFullyQualifiedClassName(tag) -> tag
                    tag == "view" -> attributes.getValue("class")?.takeIf(::isFullyQualifiedClassName)
                    else -> null
                } ?: return
                output += ExternalNameCandidate(
                    ExternalNameContractKind.LAYOUT_CUSTOM_VIEW,
                    relative,
                    locator?.lineNumber ?: 1,
                    symbol,
                )
            }
        })
    }

    private fun scanXml(path: Path, handler: DefaultHandler) {
        val factory = SAXParserFactory.newInstance().apply {
            isNamespaceAware = true
            setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
            setFeature("http://xml.org/sax/features/external-general-entities", false)
            setFeature("http://xml.org/sax/features/external-parameter-entities", false)
        }
        val reader = factory.newSAXParser().xmlReader.apply {
            setProperty("http://javax.xml.XMLConstants/property/accessExternalDTD", "")
            setProperty("http://javax.xml.XMLConstants/property/accessExternalSchema", "")
            contentHandler = handler
        }
        Files.newInputStream(path).use { input -> reader.parse(InputSource(input)) }
    }

    private fun resolveManifestName(name: String, manifestPackage: String): String = when {
        name.startsWith('.') -> manifestPackage + name
        '.' !in name -> "$manifestPackage.$name"
        else -> name
    }

    private fun isFullyQualifiedClassName(value: String): Boolean = FULLY_QUALIFIED_CLASS.matches(value)

    private fun stringConstants(source: String): Map<String, String> {
        val expressions = linkedMapOf<String, String>()
        KOTLIN_CONSTANT.findAll(source).forEach { expressions[it.groupValues[1]] = it.groupValues[2].trim() }
        JAVA_CONSTANT.findAll(source).forEach { expressions[it.groupValues[1]] = it.groupValues[2].trim() }
        val result = linkedMapOf<String, String>()
        repeat(expressions.size + 1) {
            expressions.forEach { (name, expression) ->
                if (name !in result) evaluateString(expression, result)?.let { result[name] = it }
            }
        }
        return result
    }

    private fun evaluateString(expression: String, constants: Map<String, String>): String? {
        val parts = splitTopLevel(expression.trim(), '+')
        if (parts.size > 1) return parts.map { evaluateString(it, constants) ?: return null }.joinToString("")
        val value = stripParentheses(parts.singleOrNull()?.trim().orEmpty())
        decodeString(value)?.let { return it }
        val identifier = IDENTIFIER.matchEntire(value)?.value ?: return null
        return constants[identifier] ?: constants[identifier.substringAfterLast('.')]
    }

    private fun decodeString(value: String): String? {
        if (value.startsWith("\"\"\"") && value.endsWith("\"\"\"") && value.length >= 6) {
            val body = value.substring(3, value.length - 3)
            if (KOTLIN_TEMPLATE.containsMatchIn(body)) return null
            return body
        }
        if (!(value.startsWith('"') && value.endsWith('"') && value.length >= 2)) return null
        val body = value.substring(1, value.length - 1)
        if (hasKotlinTemplate(body)) return null
        return decodeEscapes(body)
    }

    private fun hasKotlinTemplate(body: String): Boolean {
        var escaped = false
        body.forEach { character ->
            if (character == '$' && !escaped) return true
            escaped = character == '\\' && !escaped
            if (character != '\\') escaped = false
        }
        return false
    }

    private fun decodeEscapes(value: String): String? = runCatching {
        buildString {
            var index = 0
            while (index < value.length) {
                val character = value[index++]
                if (character != '\\') {
                    append(character)
                    continue
                }
                require(index < value.length)
                when (val escaped = value[index++]) {
                    '\\', '"', '\'' -> append(escaped)
                    'n' -> append('\n')
                    'r' -> append('\r')
                    't' -> append('\t')
                    'b' -> append('\b')
                    'f' -> append('\u000c')
                    '$' -> append('$')
                    'u' -> {
                        require(index + 4 <= value.length)
                        append(value.substring(index, index + 4).toInt(16).toChar())
                        index += 4
                    }
                    else -> error("unsupported string escape: $escaped")
                }
            }
        }
    }.getOrNull()

    private fun stripParentheses(value: String): String {
        var result = value
        while (result.startsWith('(') && result.endsWith(')') && matchingParen(result, 0) == result.lastIndex) {
            result = result.substring(1, result.lastIndex).trim()
        }
        return result
    }

    private fun splitArguments(value: String): List<String> =
        if (value.isBlank()) emptyList() else splitTopLevel(value, ',').map(String::trim)

    private fun splitTopLevel(value: String, delimiter: Char): List<String> {
        val result = mutableListOf<String>()
        var start = 0
        var round = 0
        var square = 0
        var curly = 0
        var index = 0
        var quote: Char? = null
        var triple = false
        var escaped = false
        while (index < value.length) {
            val character = value[index]
            if (quote != null) {
                if (triple && value.startsWith("\"\"\"", index)) {
                    index += 3
                    quote = null
                    triple = false
                    continue
                }
                if (!triple && character == quote && !escaped) quote = null
                escaped = !triple && character == '\\' && !escaped
                if (character != '\\') escaped = false
                index++
                continue
            }
            if (value.startsWith("\"\"\"", index)) {
                quote = '"'; triple = true; index += 3; continue
            }
            if (character == '"' || character == '\'') {
                quote = character; escaped = false; index++; continue
            }
            when (character) {
                '(' -> round++
                ')' -> round--
                '[' -> square++
                ']' -> square--
                '{' -> curly++
                '}' -> curly--
                delimiter -> if (round == 0 && square == 0 && curly == 0) {
                    result += value.substring(start, index)
                    start = index + 1
                }
            }
            index++
        }
        result += value.substring(start)
        return result
    }

    private fun matchingParen(source: String, open: Int): Int {
        if (open !in source.indices || source[open] != '(') return -1
        var depth = 0
        var index = open
        var quote: Char? = null
        var triple = false
        var escaped = false
        while (index < source.length) {
            val character = source[index]
            if (quote != null) {
                if (triple && source.startsWith("\"\"\"", index)) {
                    index += 3; quote = null; triple = false; continue
                }
                if (!triple && character == quote && !escaped) quote = null
                escaped = !triple && character == '\\' && !escaped
                if (character != '\\') escaped = false
                index++
                continue
            }
            if (source.startsWith("\"\"\"", index)) {
                quote = '"'; triple = true; index += 3; continue
            }
            if (character == '"' || character == '\'') {
                quote = character; index++; continue
            }
            if (character == '(') depth++
            if (character == ')') {
                depth--
                if (depth == 0) return index
            }
            index++
        }
        return -1
    }

    private fun mask(source: String): LexicalSource {
        val cleaned = source.toCharArray()
        val code = source.toCharArray()
        var index = 0
        var state = LexicalState.CODE
        var blockDepth = 0
        while (index < source.length) {
            val character = source[index]
            when (state) {
                LexicalState.CODE -> when {
                    source.startsWith("//", index) -> { blank(cleaned, index, 2); blank(code, index, 2); index += 2; state = LexicalState.LINE_COMMENT }
                    source.startsWith("/*", index) -> { blank(cleaned, index, 2); blank(code, index, 2); index += 2; blockDepth = 1; state = LexicalState.BLOCK_COMMENT }
                    source.startsWith("\"\"\"", index) -> { blank(code, index, 3); index += 3; state = LexicalState.TRIPLE_STRING }
                    character == '"' -> { code[index] = ' '; index++; state = LexicalState.STRING }
                    character == '\'' -> { code[index] = ' '; index++; state = LexicalState.CHAR }
                    else -> index++
                }
                LexicalState.LINE_COMMENT -> {
                    if (character == '\n') state = LexicalState.CODE else { cleaned[index] = ' '; code[index] = ' ' }
                    index++
                }
                LexicalState.BLOCK_COMMENT -> when {
                    source.startsWith("/*", index) -> { blockDepth++; blank(cleaned, index, 2); blank(code, index, 2); index += 2 }
                    source.startsWith("*/", index) -> { blockDepth--; blank(cleaned, index, 2); blank(code, index, 2); index += 2; if (blockDepth == 0) state = LexicalState.CODE }
                    else -> { if (character != '\n') { cleaned[index] = ' '; code[index] = ' ' }; index++ }
                }
                LexicalState.STRING, LexicalState.CHAR -> {
                    code[index] = if (character == '\n') '\n' else ' '
                    if (character == '\\') {
                        if (index + 1 < source.length) code[index + 1] = if (source[index + 1] == '\n') '\n' else ' '
                        index += 2
                    } else {
                        val closing = (state == LexicalState.STRING && character == '"') || (state == LexicalState.CHAR && character == '\'')
                        index++
                        if (closing) state = LexicalState.CODE
                    }
                }
                LexicalState.TRIPLE_STRING -> {
                    if (source.startsWith("\"\"\"", index)) {
                        blank(code, index, 3); index += 3; state = LexicalState.CODE
                    } else {
                        code[index] = if (character == '\n') '\n' else ' '; index++
                    }
                }
            }
        }
        return LexicalSource(String(cleaned), String(code))
    }

    private fun blank(chars: CharArray, start: Int, count: Int) {
        for (index in start until minOf(start + count, chars.size)) if (chars[index] != '\n') chars[index] = ' '
    }

    private fun classDeclarations(source: String): List<Pair<String, Int>> = CLASS_DECLARATION.findAll(source)
        .map { it.groupValues[1] to it.range.first }
        .toList()

    private fun nextClass(source: String, start: Int): Pair<String, Int>? = CLASS_DECLARATION.find(source, start)?.let {
        it.groupValues[1] to it.range.first
    }

    private fun nextFunction(source: String, start: Int): Pair<String, Int>? = FUNCTION.find(source, start)?.let {
        it.groupValues.drop(1).first(String::isNotBlank) to it.range.first
    }

    private fun candidate(kind: ExternalNameContractKind, file: String, source: String, offset: Int, symbol: String) =
        ExternalNameCandidate(kind, file, line(source, offset), symbol)

    private fun isModelLike(path: String, source: String): Boolean =
        path.split('/').any { it.equals("model", true) || it.equals("bean", true) } ||
            source.contains("com.google.gson") || source.contains("Gson")

    private fun previousDelimiter(source: String, offset: Int): Int = maxOf(
        source.lastIndexOf(',', offset - 1),
        source.lastIndexOf('\n', offset - 1),
        source.lastIndexOf(';', offset - 1),
    ) + 1

    private fun line(source: String, offset: Int): Int = source.substring(0, offset.coerceIn(0, source.length)).count { it == '\n' } + 1
    private fun portable(path: Path): String = path.toString().replace('\\', '/')

    private data class SelectedAppResource(
        val path: Path,
        val relativePath: String,
        val logicalName: String,
        val layer: Int,
    )
    private data class Resolution(
        val value: String,
        val ownerInternalName: String? = null,
        val jvmDescriptor: String? = null,
    )
    private data class ManifestClassDeclaration(val name: String, val line: Int)
    private data class LexicalSource(val cleaned: String, val mask: String)
    private data class CallPattern(
        val kind: ResolvedContractKind,
        val unresolvedKind: UnresolvedContractKind,
        val regex: Regex,
    )
    private enum class LexicalState { CODE, LINE_COMMENT, BLOCK_COMMENT, STRING, CHAR, TRIPLE_STRING }

    private companion object {
        val STRING_LITERAL = Regex("\\\"([^\\\"\\\\]*(?:\\\\.[^\\\"\\\\]*)*)\\\"")
        val URL_LITERAL = Regex("https?://[^\\s\\\"<>]+")
        val URI_LITERAL = Regex("[A-Za-z][A-Za-z0-9+.-]*://[^\\s\\\"<>]+")
        val ROUTE_LITERAL = Regex("route:[A-Za-z0-9_./-]+")
        val FILE_NAME_LITERAL = Regex("[A-Za-z0-9_./-]+\\.(?:json|xml|html|txt|properties|db|jpg|jpeg|png|webp)")
        val EXCLUDED_RESOURCE_COMPONENTS = setOf("build", "generated", "test", "androidtest", "testfixtures")
        val EXCLUDED_PATH_COMPONENTS = setOf("build", "generated", "test", "androidtest", "testfixtures")
        val PACKAGE_DECLARATION = Regex("(?m)^\\s*package\\s+([A-Za-z_][A-Za-z0-9_.]*)\\s*;?")
        const val ANDROID_NS = "http://schemas.android.com/apk/res/android"
        val EXPORTED_COMPONENT_TAGS = setOf("activity", "service", "receiver", "provider")
        val FULLY_QUALIFIED_CLASS = Regex("""[A-Za-z_][\w${'$'}]*(?:\.[A-Za-z_][\w${'$'}]*)+""")
        val CALLS = listOf(
            CallPattern(ResolvedContractKind.CLASS_FOR_NAME, UnresolvedContractKind.APP_REFLECTION, Regex("""\b(?:java\s*\.\s*lang\s*\.\s*)?Class\s*\.\s*forName\s*\(""")),
            CallPattern(ResolvedContractKind.CLASS_LOADER, UnresolvedContractKind.APP_REFLECTION, Regex("""\.\s*loadClass\s*\(""")),
            CallPattern(ResolvedContractKind.METHOD, UnresolvedContractKind.APP_REFLECTION, Regex("""\.\s*(?:getDeclaredMethod|getMethod)\s*\(""")),
            CallPattern(ResolvedContractKind.FIELD, UnresolvedContractKind.APP_REFLECTION, Regex("""\.\s*(?:getDeclaredField|getField)\s*\(""")),
            CallPattern(ResolvedContractKind.RESOURCE_IDENTIFIER, UnresolvedContractKind.RESOURCE_LOOKUP, Regex("""\.\s*getIdentifier\s*\(""")),
        )
        val GSON_FIELD_NAMING_STRATEGY = Regex("""\.\s*setFieldNamingStrategy\s*\(""")
        val BUILT_IN_FIELD_NAMING_POLICY = Regex(
            """(?:com\.google\.gson\.)?FieldNamingPolicy\.[A-Z][A-Z0-9_]*""",
        )
        val KOTLIN_CONSTANT = Regex("""(?m)\bconst\s+val\s+([A-Za-z_${'$'}][\w${'$'}]*)\s*(?::\s*String\s*)?=\s*([^\r\n;]+)""")
        val JAVA_CONSTANT = Regex("""(?s)\bstatic\s+final\s+(?:java\.lang\.)?String\s+([A-Za-z_${'$'}][\w${'$'}]*)\s*=\s*([^;]+);""")
        val IMPORT = Regex("""(?m)^\s*import\s+([A-Za-z_][\w.]*)\s*;?""")
        val IDENTIFIER = Regex("""[A-Za-z_${'$'}][\w${'$'}]*(?:\.[A-Za-z_${'$'}][\w${'$'}]*)*""")
        val IDENTIFIER_RECEIVER = Regex("""([A-Za-z_${'$'}][\w${'$'}]*)\s*$""")
        val CLASS_RECEIVER = Regex("""([A-Za-z_${'$'}][\w${'$'}]*(?:\.[A-Za-z_${'$'}][\w${'$'}]*)*(?:::class\.java(?:PrimitiveType|ObjectType)?|\.class))\s*$""")
        val CLASS_FOR_NAME_ASSIGNMENT = Regex(
            """(?m)(?:\b(?:val|var)\s+|\bClass\s*(?:<[^;\r\n=]+>)?\s+)([A-Za-z_${'$'}][\w${'$'}]*)[^=\r\n;]*=\s*(?:java\.lang\.)?Class\.forName\s*\(([^)\r\n;]+)\)""",
        )
        val JAVA_BOUNDED_CLASS_ASSIGNMENT = Regex(
            """\bClass\s*<\s*\?\s+extends\s+([A-Za-z_${'$'}][\w${'$'}.]*)\s*>\s+([A-Za-z_${'$'}][\w${'$'}]*)\s*=""",
        )
        val KOTLIN_CLASS_NAME = Regex("""([A-Za-z_${'$'}][\w${'$'}]*(?:\.[A-Za-z_${'$'}][\w${'$'}]*)*)::class\.java\.name""")
        val JAVA_CLASS_NAME = Regex("""([A-Za-z_${'$'}][\w${'$'}]*(?:\.[A-Za-z_${'$'}][\w${'$'}]*)*)\.class\.getName\(\)""")
        val JAVA_CLASS_LITERAL = Regex("""([A-Za-z_${'$'}][\w${'$'}]*(?:\.[A-Za-z_${'$'}][\w${'$'}]*)*)\.class""")
        val KOTLIN_CLASS_LITERAL = Regex("""([A-Za-z_${'$'}][\w${'$'}]*(?:\.[A-Za-z_${'$'}][\w${'$'}]*)*)::class\.java(PrimitiveType|ObjectType)?""")
        val KOTLIN_TEMPLATE = Regex("""\${'$'}\{|\${'$'}[A-Za-z_]""")
        val SERIALIZABLE = Regex("""(?:\bimplements\s+|[:,]\s*)(?:java\.io\.)?Serializable\b""")
        val ENTITY = Regex("""@(?:io\.objectbox\.annotation\.)?Entity\b""")
        val JAVASCRIPT = Regex("""@(?:android\.webkit\.)?JavascriptInterface\b""")
        val NATIVE_FUNCTION = Regex("""\bexternal\s+fun\s+([A-Za-z_${'$'}][\w${'$'}]*)|\bnative\s+[\w<>,.?\[\] ]+\s+([A-Za-z_${'$'}][\w${'$'}]*)\s*\(""")
        val CLASS_DECLARATION = Regex("""\b(?:data\s+|sealed\s+|enum\s+|open\s+|abstract\s+)?class\s+([A-Za-z_${'$'}][\w${'$'}]*)""")
        val FUNCTION = Regex("""\bfun\s+([A-Za-z_${'$'}][\w${'$'}]*)|\b(?:public\s+|protected\s+|private\s+)?[\w<>,.?\[\] ]+\s+([A-Za-z_${'$'}][\w${'$'}]*)\s*\(""")
        val PROPERTY = Regex("""\b(?:val|var)\s+([A-Za-z_${'$'}][\w${'$'}]*)\b""")
        val ANDROID_FIELD_HELPER_CLASS = Regex(
            """\bclass\s+[A-Za-z_${'$'}][\w${'$'}]*[^\r\n{]*(?::|extends)\s*(?:android\.widget\.)?Toast\b""",
        )
        val ANDROID_FIELD_HELPER_RECEIVER = Regex(
            """\b(?:var\s+superClass\s*:\s*Class<\*>|Class<\?>\s+superClass)\s*=\s*obj\.javaClass""",
        )
        val SERIALIZED_NAME = Regex("""@(?:com\.google\.gson\.annotations\.)?SerializedName\s*\(""")
        val KOTLIN_TYPES = mapOf("String" to "java.lang.String", "Any" to "java.lang.Object")
        val KOTLIN_PRIMITIVES = mapOf(
            "Boolean" to "boolean", "Byte" to "byte", "Char" to "char", "Short" to "short",
            "Int" to "int", "Long" to "long", "Float" to "float", "Double" to "double",
        )
        val JVM_PRIMITIVE_DESCRIPTORS = mapOf(
            "boolean" to "Z",
            "byte" to "B",
            "char" to "C",
            "short" to "S",
            "int" to "I",
            "long" to "J",
            "float" to "F",
            "double" to "D",
            "void" to "V",
        )
    }
}
