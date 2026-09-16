package com.holin.android.hardening

import com.android.build.api.dsl.AndroidSourceDirectorySet
import com.android.build.api.dsl.ApplicationExtension
import com.android.build.api.dsl.LibraryExtension
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.Collections
import javax.inject.Inject
import org.gradle.api.Action
import org.gradle.api.Project
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.model.ObjectFactory
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.MapProperty
import org.gradle.api.provider.Property
import org.gradle.api.provider.SetProperty

private fun <T> immutableSet(values: Iterable<T>): Set<T> =
    Collections.unmodifiableSet(LinkedHashSet<T>().apply { addAll(values) })

private class ExplicitListProperty<T : Any>(
    private val delegate: ListProperty<T>,
    private val explicitlyConfigured: Property<Boolean>,
) : ListProperty<T> by delegate {
    override fun set(elements: Iterable<T>?) {
        delegate.set(elements)
        explicitlyConfigured.set(true)
    }

    override fun set(provider: org.gradle.api.provider.Provider<out Iterable<T>>) {
        delegate.set(provider)
        explicitlyConfigured.set(true)
    }

    override fun value(elements: Iterable<T>?): ListProperty<T> {
        set(elements)
        return this
    }

    override fun value(provider: org.gradle.api.provider.Provider<out Iterable<T>>): ListProperty<T> {
        set(provider)
        return this
    }

    override fun empty(): ListProperty<T> {
        delegate.empty()
        explicitlyConfigured.set(true)
        return this
    }

    override fun add(element: T) {
        prepareAppend()
        delegate.add(element)
    }

    override fun add(provider: org.gradle.api.provider.Provider<out T>) {
        prepareAppend()
        delegate.add(provider)
    }

    override fun addAll(vararg elements: T) {
        prepareAppend()
        delegate.addAll(*elements)
    }

    override fun addAll(elements: Iterable<T>) {
        prepareAppend()
        delegate.addAll(elements)
    }

    override fun addAll(provider: org.gradle.api.provider.Provider<out Iterable<T>>) {
        prepareAppend()
        delegate.addAll(provider)
    }

    override fun convention(elements: Iterable<T>?): ListProperty<T> {
        delegate.convention(elements)
        return this
    }

    override fun convention(provider: org.gradle.api.provider.Provider<out Iterable<T>>): ListProperty<T> {
        delegate.convention(provider)
        return this
    }

    override fun unset(): ListProperty<T> {
        delegate.unset()
        explicitlyConfigured.set(false)
        return this
    }

    override fun unsetConvention(): ListProperty<T> {
        delegate.unsetConvention()
        return this
    }

    private fun prepareAppend() {
        if (!explicitlyConfigured.get()) {
            delegate.empty()
            explicitlyConfigured.set(true)
        }
    }
}

/** Immutable, project-resolved definition of source and resource ownership. */
class HardeningOwnership internal constructor(
    modules: List<OwnedModule>,
    generatedPackagePrefixes: Set<String>,
    excludedPackagePrefixes: Set<String>,
    hardcodedReferences: HardcodedReferenceScope = HardcodedReferenceScope.defaults(),
) {
    val modules: List<OwnedModule> = Collections.unmodifiableList(modules.map(OwnedModule::snapshot))
    val generatedPackagePrefixes: Set<String> = immutableSet(generatedPackagePrefixes)
    val excludedPackagePrefixes: Set<String> = immutableSet(excludedPackagePrefixes)
    val deniedDexDescriptorPrefixes: Set<String> = immutableSet(
        (this.generatedPackagePrefixes + this.excludedPackagePrefixes).map { prefix ->
            "L${prefix.replace('.', '/')}/"
        },
    )
    val hardcodedReferences: HardcodedReferenceScope = hardcodedReferences.snapshot()
    val modulePaths: Set<String> = immutableSet(this.modules.map(OwnedModule::path))

    fun priority(path: String): Int = modules.indexOfFirst { it.path == path }
        .takeIf { it >= 0 }
        ?: throw IllegalArgumentException("module $path is outside the hardening ownership scope")

    fun requireContains(paths: Set<String>, label: String) {
        require(paths.isNotEmpty() && paths.all(modulePaths::contains)) {
            "$label must be selected from ${modulePaths.sorted()}"
        }
    }

    fun isWebpIncluded(module: String, moduleRelativePath: String): Boolean =
        modules.firstOrNull { it.path == module }?.images?.includes(moduleRelativePath, ImageFormat.WEBP) == true

    fun isImageIncluded(module: String, moduleRelativePath: String, format: ImageFormat): Boolean =
        modules.firstOrNull { it.path == module }?.images?.includes(moduleRelativePath, format) == true

    fun requireMatchedWebpIncludes(candidates: Map<String, Set<String>>) {
        modules.forEach { module ->
            val paths = candidates[module.path].orEmpty()
            module.webp.includes.forEach { pattern ->
                require(paths.any { module.webp.matchesInclude(pattern, it) }) {
                    "ownership module ${module.path} WebP include matched no owned WebP: $pattern"
                }
            }
        }
    }

    fun requireMatchedImageIncludes(candidates: Map<String, Set<String>>) {
        modules.forEach { module ->
            val paths = candidates[module.path].orEmpty()
            module.images.includes.forEach { pattern ->
                require(paths.any { module.images.matchesInclude(pattern, it) &&
                    module.images.formats.any { format -> imageFormatForPath(it) == format } }) {
                    "ownership module ${module.path} image include matched no owned image: $pattern"
                }
            }
        }
    }

    fun requireMatchedHardcodedReferenceIncludes(candidates: Map<String, Set<String>>) {
        if (!hardcodedReferences.requireExplicitIncludeMatches) return
        modules.forEach { module ->
            val paths = candidates[module.path].orEmpty()
            hardcodedReferences.includeGlobs.forEach { pattern ->
                require(paths.any { hardcodedReferences.matchesInclude(pattern, it) }) {
                    "ownership hardcoded reference include matched no eligible owned production file " +
                        "for module ${module.path}: $pattern"
                }
            }
        }
    }

    class OwnedModule(
        val path: String,
        directory: Path,
        sourceSets: Set<String>,
        sourceRoots: ResolvedSourceRoots = ResolvedSourceRoots.conventional(directory, sourceSets),
        webp: WebpScope = WebpScope.none(),
        images: ImageScope = ImageScope.none(),
    ) {
        val directory: Path = directory.toAbsolutePath().normalize()
        val sourceSets: Set<String> = immutableSet(sourceSets)
        val sourceRoots: ResolvedSourceRoots = sourceRoots.snapshot()
        val webp: WebpScope = webp.snapshot()
        val images: ImageScope = ImageScope.merge(images, this.webp)

        internal fun snapshot(): OwnedModule = OwnedModule(path, directory, sourceSets, sourceRoots, webp, images)
    }

    class ResolvedSourceRoots(
        javaDirectories: Set<Path>,
        kotlinDirectories: Set<Path>,
        resourceDirectories: Set<Path>,
        manifestFiles: Set<Path>,
        sourceSets: List<ResolvedSourceSetRoots> = emptyList(),
    ) {
        val javaDirectories: Set<Path> = normalizedPaths(javaDirectories)
        val kotlinDirectories: Set<Path> = normalizedPaths(kotlinDirectories)
        val resourceDirectories: Set<Path> = normalizedPaths(resourceDirectories)
        val manifestFiles: Set<Path> = normalizedPaths(manifestFiles)
        val sourceSets: List<ResolvedSourceSetRoots> =
            Collections.unmodifiableList(sourceSets.map(ResolvedSourceSetRoots::snapshot))
        val all: Set<Path> = immutableSet(
            this.javaDirectories + this.kotlinDirectories + this.resourceDirectories + this.manifestFiles,
        )

        internal fun snapshot(): ResolvedSourceRoots = ResolvedSourceRoots(
            javaDirectories,
            kotlinDirectories,
            resourceDirectories,
            manifestFiles,
            sourceSets,
        )

        companion object {
            internal fun conventional(directory: Path, sourceSets: Set<String>): ResolvedSourceRoots {
                val module = directory.toAbsolutePath().normalize()
                return fromSourceSets(
                    sourceSets.map { sourceSet ->
                        ResolvedSourceSetRoots(
                            sourceSet,
                            setOf(module.resolve("src/$sourceSet/java")),
                            setOf(module.resolve("src/$sourceSet/kotlin")),
                            setOf(module.resolve("src/$sourceSet/res")),
                            setOf(module.resolve("src/$sourceSet/AndroidManifest.xml")),
                        )
                    },
                )
            }

            internal fun fromSourceSets(sourceSets: List<ResolvedSourceSetRoots>): ResolvedSourceRoots =
                ResolvedSourceRoots(
                    sourceSets.flatMapTo(linkedSetOf(), ResolvedSourceSetRoots::javaDirectories),
                    sourceSets.flatMapTo(linkedSetOf(), ResolvedSourceSetRoots::kotlinDirectories),
                    sourceSets.flatMapTo(linkedSetOf(), ResolvedSourceSetRoots::resourceDirectories),
                    sourceSets.flatMapTo(linkedSetOf(), ResolvedSourceSetRoots::manifestFiles),
                    sourceSets,
                )

            private fun normalizedPaths(paths: Set<Path>): Set<Path> = immutableSet(
                paths.map { it.toAbsolutePath().normalize() },
            )
        }
    }

    class ResolvedSourceSetRoots(
        val name: String,
        javaDirectories: Set<Path>,
        kotlinDirectories: Set<Path>,
        resourceDirectories: Set<Path>,
        manifestFiles: Set<Path>,
    ) {
        val javaDirectories: Set<Path> = normalizedPaths(javaDirectories)
        val kotlinDirectories: Set<Path> = normalizedPaths(kotlinDirectories)
        val resourceDirectories: Set<Path> = normalizedPaths(resourceDirectories)
        val manifestFiles: Set<Path> = normalizedPaths(manifestFiles)

        internal fun snapshot(): ResolvedSourceSetRoots = ResolvedSourceSetRoots(
            name,
            javaDirectories,
            kotlinDirectories,
            resourceDirectories,
            manifestFiles,
        )

        private companion object {
            fun normalizedPaths(paths: Set<Path>): Set<Path> = immutableSet(
                paths.map { it.toAbsolutePath().normalize() },
            )
        }
    }

    class WebpScope private constructor(
        includes: Collection<String>,
        excludes: Collection<String>,
    ) {
        val includes: Set<String> = immutableSet(includes)
        val excludes: Set<String> = immutableSet(excludes)
        private val includeMatchers = this.includes.associateWith(::globRegex)
        private val excludeMatchers = this.excludes.associateWith(::globRegex)

        fun includes(moduleRelativePath: String): Boolean {
            val normalized = normalizeCandidate(moduleRelativePath)
            return includeMatchers.values.any { it.matches(normalized) } &&
                excludeMatchers.values.none { it.matches(normalized) }
        }

        internal fun matchesInclude(pattern: String, moduleRelativePath: String): Boolean =
            requireNotNull(includeMatchers[pattern]).matches(normalizeCandidate(moduleRelativePath))

        internal fun snapshot(): WebpScope = WebpScope(includes, excludes)

        companion object {
            fun resolve(includes: Collection<String>, excludes: Collection<String>): WebpScope = WebpScope(
                normalizePatterns(includes, "include"),
                normalizePatterns(excludes, "exclude"),
            )

            internal fun none(): WebpScope = WebpScope(emptySet(), emptySet())

            private fun normalizePatterns(patterns: Collection<String>, kind: String): List<String> {
                val normalized = patterns.map(::normalizePattern)
                require(normalized.distinct().size == normalized.size) {
                    "ownership contains duplicate WebP $kind pattern after normalization"
                }
                return normalized
            }

            private fun normalizePattern(pattern: String): String {
                require(pattern.isNotBlank()) { "WebP patterns must not be blank" }
                require('\\' !in pattern) { "WebP patterns must use '/' separators: $pattern" }
                val trimmed = pattern.trim()
                require(!trimmed.startsWith('/') && !WINDOWS_ABSOLUTE.matches(trimmed)) {
                    "WebP patterns must be module-relative: $pattern"
                }
                val components = trimmed.split('/').filterNot { it.isEmpty() || it == "." }
                require(components.isNotEmpty() && ".." !in components) {
                    "WebP patterns must not escape the module: $pattern"
                }
                return components.joinToString("/")
            }

            private fun normalizeCandidate(path: String): String {
                require(path.isNotBlank() && '\\' !in path && !path.startsWith('/') && !WINDOWS_ABSOLUTE.matches(path)) {
                    "WebP candidate path must be module-relative: $path"
                }
                val components = path.split('/').filterNot { it.isEmpty() || it == "." }
                require(components.isNotEmpty() && ".." !in components) {
                    "WebP candidate path must not escape the module: $path"
                }
                return components.joinToString("/")
            }

            private fun globRegex(pattern: String): Regex {
                val regex = StringBuilder("^")
                var index = 0
                while (index < pattern.length) {
                    when {
                        pattern.startsWith("**/", index) -> {
                            regex.append("(?:.*/)?")
                            index += 3
                        }
                        pattern.startsWith("**", index) -> {
                            regex.append(".*")
                            index += 2
                        }
                        pattern[index] == '*' -> {
                            regex.append("[^/]*")
                            index++
                        }
                        pattern[index] == '?' -> {
                            regex.append("[^/]")
                            index++
                        }
                        else -> {
                            regex.append(Regex.escape(pattern[index].toString()))
                            index++
                        }
                    }
                }
                return Regex(regex.append('$').toString())
            }

            private val WINDOWS_ABSOLUTE = Regex("^[A-Za-z]:/.*")
        }
    }

    class ImageScope private constructor(
        includes: Collection<String>,
        excludes: Collection<String>,
        formats: Collection<ImageFormat>,
        private val legacyWebpIncludes: Set<String> = emptySet(),
        private val legacyWebpExcludes: Set<String> = emptySet(),
    ) {
        val includes: Set<String> = immutableSet(includes)
        val excludes: Set<String> = immutableSet(excludes)
        val formats: Set<ImageFormat> = immutableSet(formats)
        private val includeMatchers = this.includes.associateWith(::globRegex)
        private val excludeMatchers = this.excludes.associateWith(::globRegex)
        private val legacyWebpIncludeMatchers = legacyWebpIncludes.associateWith(::globRegex)
        private val legacyWebpExcludeMatchers = legacyWebpExcludes.associateWith(::globRegex)

        fun includes(moduleRelativePath: String, format: ImageFormat): Boolean {
            val normalized = normalizeCandidate(moduleRelativePath)
            val explicitlyIncluded = includeMatchers.values.any { it.matches(normalized) } ||
                (format == ImageFormat.WEBP && legacyWebpIncludeMatchers.values.any { it.matches(normalized) })
            val excluded = excludeMatchers.values.any { it.matches(normalized) } ||
                (format == ImageFormat.WEBP && legacyWebpExcludeMatchers.values.any { it.matches(normalized) })
            val formatEnabled = format in formats ||
                (format == ImageFormat.WEBP && legacyWebpIncludes.isNotEmpty())
            return formatEnabled && explicitlyIncluded && !excluded
        }

        internal fun matchesInclude(pattern: String, moduleRelativePath: String): Boolean =
            requireNotNull(includeMatchers[pattern]).matches(normalizeCandidate(moduleRelativePath)) &&
                excludeMatchers.values.none { it.matches(normalizeCandidate(moduleRelativePath)) }

        internal fun snapshot(): ImageScope = ImageScope(includes, excludes, formats, legacyWebpIncludes, legacyWebpExcludes)

        companion object {
            fun resolve(
                includes: Collection<String>,
                excludes: Collection<String>,
                formats: Collection<ImageFormat>,
            ): ImageScope = ImageScope(
                normalizePatterns(includes, "include"),
                normalizePatterns(excludes, "exclude"),
                formats.toSet(),
            )

            internal fun none(): ImageScope = ImageScope(emptySet(), emptySet(), emptySet())

            internal fun merge(images: ImageScope, webp: WebpScope): ImageScope = ImageScope(
                images.includes,
                images.excludes,
                images.formats,
                webp.includes,
                webp.excludes,
            )

            private fun normalizePatterns(patterns: Collection<String>, kind: String): List<String> {
                val normalized = patterns.map(::normalizePattern)
                require(normalized.distinct().size == normalized.size) {
                    "ownership contains duplicate image $kind pattern after normalization"
                }
                return normalized
            }

            private fun normalizePattern(pattern: String): String {
                require(pattern.isNotBlank()) { "Image patterns must not be blank" }
                require('\\' !in pattern) { "Image patterns must use '/' separators: $pattern" }
                val trimmed = pattern.trim()
                require(!trimmed.startsWith('/') && !WINDOWS_ABSOLUTE.matches(trimmed)) {
                    "Image patterns must be module-relative: $pattern"
                }
                val components = trimmed.split('/').filterNot { it.isEmpty() || it == "." }
                require(components.isNotEmpty() && ".." !in components) {
                    "Image patterns must not escape the module: $pattern"
                }
                return components.joinToString("/")
            }

            private fun normalizeCandidate(path: String): String {
                require(path.isNotBlank() && '\\' !in path && !path.startsWith('/') && !WINDOWS_ABSOLUTE.matches(path)) {
                    "Image candidate path must be module-relative: $path"
                }
                val components = path.split('/').filterNot { it.isEmpty() || it == "." }
                require(components.isNotEmpty() && ".." !in components) {
                    "Image candidate path must not escape the module: $path"
                }
                return components.joinToString("/")
            }

            private fun globRegex(pattern: String): Regex {
                val regex = StringBuilder("^")
                var index = 0
                while (index < pattern.length) {
                    when {
                        pattern.startsWith("**/", index) -> { regex.append("(?:.*/)?"); index += 3 }
                        pattern.startsWith("**", index) -> { regex.append(".*"); index += 2 }
                        pattern[index] == '*' -> { regex.append("[^/]*"); index++ }
                        pattern[index] == '?' -> { regex.append("[^/]"); index++ }
                        else -> { regex.append(Regex.escape(pattern[index].toString())); index++ }
                    }
                }
                return Regex(regex.append('$').toString())
            }

            private val WINDOWS_ABSOLUTE = Regex("^[A-Za-z]:/.*")
        }
    }

    class HardcodedReferenceScope private constructor(
        kinds: Collection<HardcodedReferenceKind>,
        includeGlobs: Collection<String>,
        excludeGlobs: Collection<String>,
        val failOnUnresolvedOwnedReference: Boolean,
        val requireExplicitIncludeMatches: Boolean,
    ) {
        val kinds: Set<HardcodedReferenceKind> = immutableSet(kinds)
        val includeGlobs: Set<String> = immutableSet(includeGlobs)
        val excludeGlobs: Set<String> = immutableSet(excludeGlobs)
        private val includeMatchers = this.includeGlobs.associateWith(::globRegex)
        private val excludeMatchers = this.excludeGlobs.associateWith(::globRegex)

        fun includes(moduleRelativePath: String): Boolean {
            val normalized = normalizeCandidate(moduleRelativePath)
            return includeMatchers.values.any { it.matches(normalized) } &&
                excludeMatchers.values.none { it.matches(normalized) }
        }

        internal fun matchesInclude(pattern: String, moduleRelativePath: String): Boolean =
            requireNotNull(includeMatchers[pattern]).matches(normalizeCandidate(moduleRelativePath))

        internal fun snapshot(): HardcodedReferenceScope = HardcodedReferenceScope(
            kinds,
            includeGlobs,
            excludeGlobs,
            failOnUnresolvedOwnedReference,
            requireExplicitIncludeMatches,
        )

        companion object {
            fun defaults(): HardcodedReferenceScope = HardcodedReferenceScope(
                HardcodedReferenceKind.values().toSet(),
                DEFAULT_INCLUDE_GLOBS,
                DEFAULT_EXCLUDE_GLOBS,
                true,
                false,
            )

            fun resolve(
                kinds: Collection<HardcodedReferenceKind>,
                includeGlobs: Collection<String>,
                excludeGlobs: Collection<String>,
                failOnUnresolvedOwnedReference: Boolean,
                requireExplicitIncludeMatches: Boolean,
            ): HardcodedReferenceScope = HardcodedReferenceScope(
                immutableSet(kinds),
                normalizePatterns(includeGlobs, "include"),
                normalizePatterns(excludeGlobs, "exclude"),
                failOnUnresolvedOwnedReference,
                requireExplicitIncludeMatches,
            )

            private fun normalizePatterns(patterns: Collection<String>, kind: String): List<String> {
                val normalized = patterns.map(::normalizePattern)
                require(normalized.distinct().size == normalized.size) {
                    "ownership contains duplicate hardcoded reference $kind pattern after normalization"
                }
                return normalized
            }

            private fun normalizePattern(pattern: String): String {
                require(pattern.isNotBlank()) { "hardcoded reference patterns must not be blank" }
                require('\\' !in pattern) { "hardcoded reference patterns must use '/' separators: $pattern" }
                val trimmed = pattern.trim()
                require(!trimmed.startsWith('/') && !WINDOWS_ABSOLUTE.matches(trimmed)) {
                    "hardcoded reference patterns must be module-relative: $pattern"
                }
                val components = trimmed.split('/').filterNot { it.isEmpty() || it == "." }
                require(components.isNotEmpty() && ".." !in components) {
                    "hardcoded reference patterns must not escape the module: $pattern"
                }
                return components.joinToString("/")
            }

            private fun normalizeCandidate(path: String): String {
                require(path.isNotBlank() && '\\' !in path && !path.startsWith('/') && !WINDOWS_ABSOLUTE.matches(path)) {
                    "hardcoded reference candidate path must be module-relative: $path"
                }
                val components = path.split('/').filterNot { it.isEmpty() || it == "." }
                require(components.isNotEmpty() && ".." !in components) {
                    "hardcoded reference candidate path must not escape the module: $path"
                }
                return components.joinToString("/")
            }

            private fun globRegex(pattern: String): Regex {
                val regex = StringBuilder("^")
                var index = 0
                while (index < pattern.length) {
                    when {
                        pattern.startsWith("**/", index) -> {
                            regex.append("(?:.*/)?")
                            index += 3
                        }
                        pattern.startsWith("**", index) -> {
                            regex.append(".*")
                            index += 2
                        }
                        pattern[index] == '*' -> {
                            regex.append("[^/]*")
                            index++
                        }
                        pattern[index] == '?' -> {
                            regex.append("[^/]")
                            index++
                        }
                        else -> {
                            regex.append(Regex.escape(pattern[index].toString()))
                            index++
                        }
                    }
                }
                return Regex(regex.append('$').toString())
            }

            internal val DEFAULT_INCLUDE_GLOBS = listOf("**/*.kt", "**/*.java", "**/*.xml")
            private val DEFAULT_EXCLUDE_GLOBS = listOf("**/test/**", "**/androidTest/**")
            private val WINDOWS_ABSOLUTE = Regex("^[A-Za-z]:/.*")
        }
    }

    companion object {
        private fun imageFormatForPath(path: String): ImageFormat? = when {
            path.endsWith(".png", true) -> ImageFormat.PNG
            path.endsWith(".webp", true) -> ImageFormat.WEBP
            path.endsWith(".jpg", true) || path.endsWith(".jpeg", true) -> ImageFormat.JPEG
            else -> null
        }
        internal fun resolve(
            rootProject: Project,
            declarations: Map<String, Set<String>>,
            webpIncludes: Map<String, Collection<String>>,
            webpExcludes: Map<String, Collection<String>>,
            manifestFiles: Map<String, Set<Path>>,
            generatedPackagePrefixes: Set<String>,
            excludedPackagePrefixes: Set<String>,
            hardcodedReferences: HardcodedReferenceScope = HardcodedReferenceScope.defaults(),
            requireAndroidModule: Boolean = true,
            imageIncludes: Map<String, Collection<String>> = emptyMap(),
            imageExcludes: Map<String, Collection<String>> = emptyMap(),
            imageFormats: Map<String, Collection<ImageFormat>> = emptyMap(),
        ): HardeningOwnership = resolveDeclarations(
            rootProject,
            declarations,
            webpIncludes,
            webpExcludes,
            manifestFiles,
            generatedPackagePrefixes,
            excludedPackagePrefixes,
            requireAndroidModule,
            hardcodedReferences,
            imageIncludes,
            imageExcludes,
            imageFormats,
        )

        internal fun resolve(
            rootProject: Project,
            declarations: Map<String, Set<String>>,
            generatedPackagePrefixes: Set<String>,
            excludedPackagePrefixes: Set<String>,
        ): HardeningOwnership = resolveDeclarations(
            rootProject,
            declarations,
            emptyMap(),
            emptyMap(),
            emptyMap(),
            generatedPackagePrefixes,
            excludedPackagePrefixes,
            false,
            HardcodedReferenceScope.defaults(),
            emptyMap(),
            emptyMap(),
            emptyMap(),
        )

        private fun resolveDeclarations(
            rootProject: Project,
            declarations: Map<String, Set<String>>,
            webpIncludes: Map<String, Collection<String>>,
            webpExcludes: Map<String, Collection<String>>,
            manifestFiles: Map<String, Set<Path>>,
            generatedPackagePrefixes: Set<String>,
            excludedPackagePrefixes: Set<String>,
            requireAndroidModule: Boolean,
            hardcodedReferences: HardcodedReferenceScope,
            imageIncludes: Map<String, Collection<String>>,
            imageExcludes: Map<String, Collection<String>>,
            imageFormats: Map<String, Collection<ImageFormat>>,
        ): HardeningOwnership {
            require(declarations.isNotEmpty()) { "androidHardening.ownership must declare at least one module" }
            val generated = validatePrefixes(generatedPackagePrefixes, "generatedPackagePrefixes")
            val excluded = validatePrefixes(excludedPackagePrefixes, "excludedPackagePrefixes")
            require(generated.none { generatedPrefix ->
                excluded.any { excludedPrefix -> prefixesOverlap(generatedPrefix, excludedPrefix) }
            }) {
                "generatedPackagePrefixes and excludedPackagePrefixes must not overlap"
            }
            val modules = declarations.entries.map { (path, sourceSets) ->
                require(MODULE_PATH.matches(path)) { "ownership module path is malformed: $path" }
                require(sourceSets.isNotEmpty()) { "ownership module $path must declare source sets" }
                val project = rootProject.findProject(path)
                    ?: throw IllegalArgumentException("ownership module project does not exist: $path")
                val validatedSourceSets = sourceSets.mapTo(linkedSetOf()) { sourceSet ->
                    require(SOURCE_SET.matches(sourceSet)) {
                        "ownership source set is malformed for $path: $sourceSet"
                    }
                    require(!isGeneratedOrTestComponent(sourceSet)) {
                        "ownership source set is not a production source set for $path: $sourceSet"
                    }
                    sourceSet
                }
                val moduleDirectory = project.projectDir.toPath().toAbsolutePath().normalize()
                val roots = if (requireAndroidModule) {
                    resolveAndroidRoots(
                        project,
                        path,
                        validatedSourceSets,
                        moduleDirectory,
                        manifestFiles[path].orEmpty(),
                    )
                } else {
                    validatedSourceSets.forEach { sourceSet ->
                        val directory = moduleDirectory.resolve("src/$sourceSet")
                        require(Files.isDirectory(directory)) {
                            "ownership source set directory does not exist: $directory"
                        }
                    }
                    ResolvedSourceRoots.conventional(moduleDirectory, validatedSourceSets)
                }
                OwnedModule(
                    path,
                    moduleDirectory,
                    validatedSourceSets,
                    roots,
                    WebpScope.resolve(webpIncludes[path].orEmpty(), webpExcludes[path].orEmpty()),
                    ImageScope.resolve(
                        imageIncludes[path].orEmpty(),
                        imageExcludes[path].orEmpty(),
                        imageFormats[path].orEmpty(),
                    ),
                )
            }
            require(modules.map(OwnedModule::path).distinct().size == modules.size) {
                "ownership contains duplicate module declarations"
            }
            return HardeningOwnership(modules, generated, excluded, hardcodedReferences)
        }

        private fun resolveAndroidRoots(
            project: Project,
            modulePath: String,
            declaredSourceSets: Set<String>,
            moduleDirectory: Path,
            explicitManifestFiles: Set<Path>,
        ): ResolvedSourceRoots {
            val sourceSets = when {
                project.pluginManager.hasPlugin("com.android.application") ->
                    project.extensions.getByType(ApplicationExtension::class.java).sourceSets
                project.pluginManager.hasPlugin("com.android.library") ->
                    project.extensions.getByType(LibraryExtension::class.java).sourceSets
                else -> throw IllegalArgumentException(
                    "ownership module $modulePath is not an Android application or library",
                )
            }
            val resolvedSourceSets = mutableListOf<ResolvedSourceSetRoots>()
            val customManifests = explicitManifestFiles.mapTo(linkedSetOf()) { manifest ->
                val normalized = manifest.toAbsolutePath().normalize()
                validateProductionPath(modulePath, moduleDirectory, normalized)
                require(Files.isRegularFile(normalized, NOFOLLOW_LINKS)) {
                    "ownership explicit manifest must be a non-symlink regular file for $modulePath: $normalized"
                }
                normalized
            }
            val highestPrioritySourceSet = declaredSourceSets.last()
            declaredSourceSets.forEach { sourceSetName ->
                val sourceSet = sourceSets.findByName(sourceSetName)
                    ?: throw IllegalArgumentException(
                        "ownership source set does not exist for $modulePath: $sourceSetName",
                    )
                val sourceSetJava = resolveDirectories(project, sourceSet.java)
                val sourceSetKotlin = resolveDirectories(project, sourceSet.kotlin)
                val sourceSetResources = resolveDirectories(project, sourceSet.res)
                val sourceSetManifests = linkedSetOf(moduleDirectory.resolve("src/$sourceSetName/AndroidManifest.xml"))
                    .apply {
                        if (sourceSetName == highestPrioritySourceSet) addAll(customManifests)
                    }
                val resolved = sourceSetJava + sourceSetKotlin + sourceSetResources + sourceSetManifests
                resolved.forEach { validateProductionPath(modulePath, moduleDirectory, it) }
                require(resolved.any(::containsProductionInput)) {
                    "ownership source set has no resolved production input for $modulePath: $sourceSetName"
                }
                resolvedSourceSets += ResolvedSourceSetRoots(
                    sourceSetName,
                    sourceSetJava,
                    sourceSetKotlin,
                    sourceSetResources,
                    sourceSetManifests,
                )
            }
            return ResolvedSourceRoots.fromSourceSets(resolvedSourceSets)
        }

        private fun resolveDirectories(project: Project, sourceDirectories: AndroidSourceDirectorySet): Set<Path> =
            sourceDirectories.directories.mapTo(linkedSetOf()) { directory ->
                project.file(directory).toPath().toAbsolutePath().normalize()
            }

        internal fun validateProductionPath(modulePath: String, moduleDirectory: Path, path: Path) {
            val normalizedModule = moduleDirectory.toAbsolutePath().normalize()
            val normalizedPath = path.toAbsolutePath().normalize()
            require(normalizedPath != normalizedModule && normalizedPath.startsWith(normalizedModule)) {
                "ownership source path escapes module $modulePath: $normalizedPath"
            }
            requireRealModuleBoundary(modulePath, normalizedModule, normalizedPath)
            val components = normalizedModule.relativize(normalizedPath).map(Path::toString)
            require(components.none(::isGeneratedOrTestComponent)) {
                "ownership source path is generated or test input for $modulePath: $normalizedPath"
            }
        }

        private fun requireRealModuleBoundary(modulePath: String, moduleDirectory: Path, path: Path) {
            val realModuleDirectory = moduleDirectory.toRealPath()
            var existing = path
            while (!Files.exists(existing, NOFOLLOW_LINKS)) {
                existing = requireNotNull(existing.parent) {
                    "ownership source path has no existing ancestor for $modulePath: $path"
                }
            }
            val realExisting = existing.toRealPath()
            require(realExisting.startsWith(realModuleDirectory)) {
                "ownership source path escapes real module boundary $modulePath: $path -> $realExisting"
            }
        }

        private fun containsProductionInput(path: Path): Boolean = when {
            Files.isRegularFile(path, NOFOLLOW_LINKS) -> true
            !Files.isDirectory(path, NOFOLLOW_LINKS) -> false
            else -> Files.walk(path).use { paths -> paths.anyMatch { Files.isRegularFile(it, NOFOLLOW_LINKS) } }
        }

        private fun validatePrefixes(prefixes: Set<String>, label: String): Set<String> =
            prefixes.mapTo(linkedSetOf()) { prefix ->
                require(PACKAGE_PREFIX.matches(prefix)) { "$label contains a blank or malformed package prefix: $prefix" }
                prefix
            }

        private fun prefixesOverlap(first: String, second: String): Boolean =
            first == second || first.startsWith("$second.") || second.startsWith("$first.")

        private fun isGeneratedOrTestComponent(component: String): Boolean {
            val tokens = component
                .replace(CAMEL_CASE_BOUNDARY, " ")
                .lowercase()
                .split(NON_ALPHANUMERIC)
                .filter(String::isNotBlank)
            return tokens.any { it == "build" || it == "generated" || it == "test" }
        }

        private val MODULE_PATH = Regex("^:(?:[A-Za-z0-9_.-]+(?::[A-Za-z0-9_.-]+)*)?$")
        private val SOURCE_SET = Regex("^[A-Za-z][A-Za-z0-9_]*$")
        private val PACKAGE_PREFIX = Regex("^[A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)*$")
        private val CAMEL_CASE_BOUNDARY = Regex("(?<=[a-z0-9])(?=[A-Z])")
        private val NON_ALPHANUMERIC = Regex("[^a-z0-9]+")
    }
}

/** Provider-backed DSL surface. Resolution is delayed until all Gradle projects are available. */
open class OwnershipSpec @Inject constructor(private val objects: ObjectFactory) {
    @Suppress("UNCHECKED_CAST")
    private val stringSetType = Set::class.java as Class<Set<String>>
    private val moduleWebpIncludes = linkedMapOf<String, List<String>>()
    private val moduleWebpExcludes = linkedMapOf<String, List<String>>()
    private val moduleImageIncludes = linkedMapOf<String, List<String>>()
    private val moduleImageExcludes = linkedMapOf<String, List<String>>()
    private val moduleImageFormats = linkedMapOf<String, Set<ImageFormat>>()
    private val moduleManifestFiles = linkedMapOf<String, ConfigurableFileCollection>()

    val modules: MapProperty<String, Set<String>> = objects.mapProperty(String::class.java, stringSetType)
        .convention(linkedMapOf())
    val generatedPackagePrefixes: SetProperty<String> = objects.setProperty(String::class.java).convention(emptySet())
    val excludedPackagePrefixes: SetProperty<String> = objects.setProperty(String::class.java).convention(emptySet())
    val hardcodedReferences: HardcodedReferenceSpec = objects.newInstance(HardcodedReferenceSpec::class.java, objects)

    fun hardcodedReferences(action: Action<in HardcodedReferenceSpec>) = action.execute(hardcodedReferences)

    internal fun declaredImageIncludes(): Map<String, List<String>> = moduleImageIncludes.toMap()
    internal fun declaredImageExcludes(): Map<String, List<String>> = moduleImageExcludes.toMap()
    internal fun declaredImageFormats(): Map<String, Set<ImageFormat>> = moduleImageFormats.toMap()

    fun module(path: String, action: Action<in OwnershipModuleSpec>) {
        val current = LinkedHashMap(modules.orNull.orEmpty())
        require(path !in current) { "ownership contains duplicate module declaration: $path" }
        val spec = objects.newInstance(OwnershipModuleSpec::class.java, objects)
        action.execute(spec)
        current[path] = LinkedHashSet(spec.sourceSets.get())
        moduleWebpIncludes[path] = spec.webp.includes.get()
        moduleWebpExcludes[path] = spec.webp.excludes.get()
        moduleImageIncludes[path] = spec.images.includes.get()
        moduleImageExcludes[path] = spec.images.excludes.get()
        moduleImageFormats[path] = spec.images.formats.get()
        moduleManifestFiles[path] = spec.manifestFiles
        modules.set(current)
    }

    internal fun resolve(rootProject: Project): HardeningOwnership = resolve(rootProject, true)

    internal fun resolvePortable(rootProject: Project): HardeningOwnership = resolve(rootProject, false)

    private fun resolve(rootProject: Project, requireAndroidModule: Boolean): HardeningOwnership = HardeningOwnership.resolve(
        rootProject,
        LinkedHashMap(modules.get()),
        LinkedHashMap(moduleWebpIncludes),
        LinkedHashMap(moduleWebpExcludes),
        moduleManifestFiles.mapValues { (_, files) ->
            files.files.mapTo(linkedSetOf()) { file -> file.toPath().toAbsolutePath().normalize() }
        },
        LinkedHashSet(generatedPackagePrefixes.get()),
        LinkedHashSet(excludedPackagePrefixes.get()),
        hardcodedReferences.resolve(),
        requireAndroidModule,
        moduleImageIncludes,
        moduleImageExcludes,
        moduleImageFormats,
    )
}

open class HardcodedReferenceSpec @Inject constructor(objects: ObjectFactory) {
    val kinds: SetProperty<HardcodedReferenceKind> = objects.setProperty(HardcodedReferenceKind::class.java)
        .convention(HardcodedReferenceKind.values().toSet())
    private val includeGlobsExplicitlyConfigured = objects.property(Boolean::class.java).convention(false)
    val includeGlobs: ListProperty<String> = ExplicitListProperty(
        objects.listProperty(String::class.java).convention(HardeningOwnership.HardcodedReferenceScope.DEFAULT_INCLUDE_GLOBS),
        includeGlobsExplicitlyConfigured,
    )
    val excludeGlobs: ListProperty<String> = objects.listProperty(String::class.java)
        .convention(listOf("**/test/**", "**/androidTest/**"))
    val failOnUnresolvedOwnedReference = objects.property(Boolean::class.java).convention(true)

    val CLASS_NAME: HardcodedReferenceKind get() = HardcodedReferenceKind.CLASS_NAME
    val MEMBER_NAME: HardcodedReferenceKind get() = HardcodedReferenceKind.MEMBER_NAME
    val RESOURCE_NAME: HardcodedReferenceKind get() = HardcodedReferenceKind.RESOURCE_NAME
    val ROUTE: HardcodedReferenceKind get() = HardcodedReferenceKind.ROUTE
    val URI: HardcodedReferenceKind get() = HardcodedReferenceKind.URI
    val URL: HardcodedReferenceKind get() = HardcodedReferenceKind.URL
    val FILE_NAME: HardcodedReferenceKind get() = HardcodedReferenceKind.FILE_NAME

    internal fun resolve(): HardeningOwnership.HardcodedReferenceScope {
        val explicitIncludes = includeGlobsExplicitlyConfigured.get()
        return HardeningOwnership.HardcodedReferenceScope.resolve(
            kinds.get(),
            includeGlobs.get(),
            excludeGlobs.get(),
            failOnUnresolvedOwnedReference.get(),
            explicitIncludes,
        )
    }
}

open class OwnershipModuleSpec @Inject constructor(objects: ObjectFactory) {
    val sourceSets: SetProperty<String> = objects.setProperty(String::class.java).convention(emptySet())
    val manifestFiles: ConfigurableFileCollection = objects.fileCollection()
    val webp: WebpScopeSpec = objects.newInstance(WebpScopeSpec::class.java, objects)
    val images: ImageScopeSpec = objects.newInstance(ImageScopeSpec::class.java, objects)

    fun webp(action: Action<in WebpScopeSpec>) = action.execute(webp)
    fun images(action: Action<in ImageScopeSpec>) = action.execute(images)
}

open class WebpScopeSpec @Inject constructor(objects: ObjectFactory) {
    val includes: ListProperty<String> = objects.listProperty(String::class.java).convention(emptyList())
    val excludes: ListProperty<String> = objects.listProperty(String::class.java).convention(emptyList())

    fun include(pattern: String) {
        includes.add(pattern)
    }

    fun exclude(pattern: String) {
        excludes.add(pattern)
    }
}

open class ImageScopeSpec @Inject constructor(objects: ObjectFactory) {
    val includes: ListProperty<String> = objects.listProperty(String::class.java).convention(emptyList())
    val excludes: ListProperty<String> = objects.listProperty(String::class.java).convention(emptyList())
    val formats: SetProperty<ImageFormat> = objects.setProperty(ImageFormat::class.java).convention(emptySet())

    fun include(pattern: String) {
        includes.add(pattern)
    }

    fun exclude(pattern: String) {
        excludes.add(pattern)
    }

    fun format(format: ImageFormat) {
        formats.add(format)
    }

    fun formats(vararg values: ImageFormat) {
        formats.addAll(values.asList())
    }

    val PNG: ImageFormat get() = ImageFormat.PNG
    val WEBP: ImageFormat get() = ImageFormat.WEBP
    val JPEG: ImageFormat get() = ImageFormat.JPEG
}
