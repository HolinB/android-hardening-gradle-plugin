package com.holin.android.hardening.inventory

import com.holin.android.hardening.HardeningOwnership
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.Locale

enum class AppSourceKind { JAVA, KOTLIN, MANIFEST, RESOURCE }

data class StaticAppSource(
    val path: Path,
    val modulePath: String,
    val sourceSet: String,
    val kind: AppSourceKind,
    val logicalName: String,
    val priority: Int,
)

class AmbiguousAppSourceException(message: String) : IllegalStateException(message)

class AppSourceInventory(
    repositoryRoot: Path,
    private val ownership: HardeningOwnership,
    private val gitIgnoreMatcher: GitIgnoreMatcher,
) {
    private val repository = repositoryRoot.toAbsolutePath().normalize()
    private val excludedPackagePaths =
        (ownership.generatedPackagePrefixes + ownership.excludedPackagePrefixes).map { it.replace('.', '/') }

    fun scan(): List<StaticAppSource> {
        val candidates = ownership.modules.flatMap(::collectModule).distinct()
        val ignored = gitIgnoreMatcher.ignored(candidates.map(StaticAppSource::path))
        val included = candidates.filter { it.path !in ignored }
        val manifests = included.filter { it.kind == AppSourceKind.MANIFEST }
        val winners = included.filterNot { it.kind == AppSourceKind.MANIFEST }
            .groupBy(::overlayKey)
            .values
            .map(::selectWinner)
        return (winners + manifests).sortedWith(
            compareBy<StaticAppSource>(
                { it.modulePath },
                { it.kind.ordinal },
                { it.logicalName },
                { -it.priority },
                { it.path.toString() },
            ),
        )
    }

    private fun collectModule(module: HardeningOwnership.OwnedModule): List<StaticAppSource> = buildList {
        val sourceSetNames = module.sourceSets.toList()
        require(sourceSetNames.isNotEmpty()) { "ownership production source sets must not be empty" }
        val resolvedSourceSets = module.sourceRoots.sourceSets
        require(resolvedSourceSets.map(HardeningOwnership.ResolvedSourceSetRoots::name) == sourceSetNames) {
            "resolved ownership source-set origins do not match ${module.path}: $sourceSetNames"
        }
        resolvedSourceSets.forEachIndexed { priority, roots ->
            roots.javaDirectories
                .forEach { collectRoot(module.path, roots.name, priority, it, AppSourceKind.JAVA, this) }
            roots.kotlinDirectories
                .forEach { collectRoot(module.path, roots.name, priority, it, AppSourceKind.KOTLIN, this) }
            roots.resourceDirectories
                .forEach { collectRoot(module.path, roots.name, priority, it, AppSourceKind.RESOURCE, this) }
            roots.manifestFiles
                .filter { Files.isRegularFile(it, NOFOLLOW_LINKS) }
                .forEach {
                    add(StaticAppSource(it, module.path, roots.name, AppSourceKind.MANIFEST, "AndroidManifest.xml", priority))
                }
        }
    }

    private fun collectRoot(
        modulePath: String,
        sourceSet: String,
        priority: Int,
        sourceRoot: Path,
        kind: AppSourceKind,
        output: MutableList<StaticAppSource>,
    ) {
        if (!Files.isDirectory(sourceRoot, NOFOLLOW_LINKS)) return
        Files.walk(sourceRoot).use { paths ->
            paths.filter { Files.isRegularFile(it, NOFOLLOW_LINKS) }.forEach { path ->
                source(path, sourceRoot, modulePath, sourceSet, priority, kind)?.let(output::add)
            }
        }
    }

    private fun source(
        path: Path,
        sourceRoot: Path,
        modulePath: String,
        sourceSet: String,
        priority: Int,
        kind: AppSourceKind,
    ): StaticAppSource? {
        require(path.toAbsolutePath().normalize().startsWith(repository)) { "owned source is outside the repository: $path" }
        val relative = portable(sourceRoot.relativize(path))
        if (relative.components().any { it in EXCLUDED_COMPONENTS }) return null
        val resolvedKind = when (kind) {
            AppSourceKind.JAVA, AppSourceKind.KOTLIN -> when {
                relative.endsWith(".java") -> AppSourceKind.JAVA
                relative.endsWith(".kt") && !relative.endsWith(".kts") -> AppSourceKind.KOTLIN
                else -> return null
            }
            AppSourceKind.RESOURCE -> AppSourceKind.RESOURCE
            AppSourceKind.MANIFEST -> error("manifests are collected directly")
        }
        val logical = if (resolvedKind == AppSourceKind.RESOURCE) relative else relative.substringBeforeLast('.')
        if (resolvedKind != AppSourceKind.RESOURCE && excludedPackagePaths.any { excluded ->
                logical == excluded || logical.startsWith("$excluded/")
            }
        ) return null
        return StaticAppSource(path, modulePath, sourceSet, resolvedKind, logical, priority)
    }

    private fun overlayKey(source: StaticAppSource): String {
        val domain = if (source.kind == AppSourceKind.RESOURCE) "resource" else "code"
        return "${source.modulePath}:$domain:${source.logicalName.lowercase(Locale.ROOT)}"
    }

    private fun selectWinner(candidates: List<StaticAppSource>): StaticAppSource {
        val highestPriority = candidates.maxOf(StaticAppSource::priority)
        val winners = candidates.filter { it.priority == highestPriority }
        if (winners.size != 1) {
            val logicalName = candidates.first().logicalName
            throw AmbiguousAppSourceException(
                "ambiguous static source winner for $logicalName at priority $highestPriority: " +
                    winners.map(StaticAppSource::path).sorted().joinToString(),
            )
        }
        return winners.single()
    }

    private fun portable(path: Path): String = path.toString().replace('\\', '/')
    private fun String.components(): List<String> = split('/').map { it.lowercase(Locale.ROOT) }

    private companion object {
        val EXCLUDED_COMPONENTS = setOf("build", "generated", "test", "androidtest", "testfixtures")
    }
}
