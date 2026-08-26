package com.holin.android.hardening

import java.nio.file.Path

internal fun testHardeningOwnership(
    repository: Path,
    modules: Set<String> = linkedSetOf(":app", ":core", ":compress", ":selector", ":ucrop"),
    sourceSets: Map<String, Set<String>> = modules.associateWith { module ->
        if (module == ":app") linkedSetOf("main", "demo") else setOf("main")
    },
    generatedPackagePrefixes: Set<String> = setOf("com.example.junkcode"),
    excludedPackagePrefixes: Set<String> = emptySet(),
    hardcodedReferences: HardeningOwnership.HardcodedReferenceScope =
        HardeningOwnership.HardcodedReferenceScope.defaults(),
): HardeningOwnership = HardeningOwnership(
    modules.map { module ->
        HardeningOwnership.OwnedModule(
            module,
            if (module == ":") {
                repository
            } else {
                repository.resolve(module.removePrefix(":").replace(':', '/'))
            },
            requireNotNull(sourceSets[module]) { "missing test source sets for $module" },
            sourceRoots(repository, module, requireNotNull(sourceSets[module])),
        )
    },
    generatedPackagePrefixes,
    excludedPackagePrefixes,
    hardcodedReferences,
)

private fun sourceRoots(repository: Path, module: String, sourceSets: Set<String>): HardeningOwnership.ResolvedSourceRoots {
    val directory = if (module == ":") repository else repository.resolve(module.removePrefix(":").replace(':', '/'))
    return HardeningOwnership.ResolvedSourceRoots.fromSourceSets(
        sourceSets.map { sourceSet ->
            val resources = linkedSetOf(directory.resolve("src/$sourceSet/res"))
            if (module == ":app" && sourceSet == "main") resources.add(directory.resolve("src/main/res-im"))
            HardeningOwnership.ResolvedSourceSetRoots(
                sourceSet,
                setOf(directory.resolve("src/$sourceSet/java")),
                setOf(directory.resolve("src/$sourceSet/kotlin")),
                resources,
                setOf(directory.resolve("src/$sourceSet/AndroidManifest.xml")),
            )
        },
    )
}
