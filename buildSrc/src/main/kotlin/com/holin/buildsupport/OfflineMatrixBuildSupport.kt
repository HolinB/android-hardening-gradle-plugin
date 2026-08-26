package com.holin.buildsupport

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.security.MessageDigest
import java.util.Comparator
import java.util.zip.ZipFile

data class OfflineMatrixArtifact(
    val group: String,
    val module: String,
    val version: String,
    val classifier: String?,
    val extension: String,
    val file: Path,
) {
    val componentKey: String = "$group:$module:$version"
    val coordinate: String = buildString {
        append(componentKey)
        classifier?.let { value -> append(":$value") }
        if (extension != "jar") append("@$extension")
    }
}

data class OfflineMatrixInput(
    val id: String,
    val agpVersion: String,
    val gradleVersion: String,
    val kotlinVersion: String,
    val aapt2Version: String,
    val lintVersion: String,
    val gradleHome: Path,
    val artifacts: List<OfflineMatrixArtifact>,
    val dependenciesByComponent: Map<String, Set<String>>,
)

object OfflineLicensePolicy {
    fun licenseFor(group: String): String = when {
        group == "com.google.protobuf" -> "BSD-3-Clause"
        group == "org.ow2.asm" -> "BSD-3-Clause"
        group == "org.slf4j" -> "MIT"
        group == "net.sf.jopt-simple" -> "MIT"
        group.startsWith("com.android.tools") -> "Apache-2.0"
        group == "com.android" || group.startsWith("com.android.") -> "Apache-2.0"
        group.startsWith("androidx.") -> "Apache-2.0"
        group.startsWith("com.google") -> "Apache-2.0"
        group.startsWith("com.squareup") -> "Apache-2.0"
        group.startsWith("org.jetbrains") -> "Apache-2.0"
        group.startsWith("org.apache") -> "Apache-2.0"
        group.startsWith("org.codehaus.groovy") -> "Apache-2.0"
        group.startsWith("org.checkerframework") -> "MIT"
        group.startsWith("org.tensorflow") -> "Apache-2.0"
        group.startsWith("org.jdom") -> "BSD-4-Clause"
        group.startsWith("net.sf.kxml") -> "BSD-3-Clause"
        group.startsWith("commons-") -> "Apache-2.0"
        group.startsWith("org.bouncycastle") -> "MIT"
        group.startsWith("javax.inject") -> "Apache-2.0"
        group.startsWith("org.bitbucket.b_c") -> "Apache-2.0"
        group.startsWith("io.grpc") -> "Apache-2.0"
        group.startsWith("io.netty") -> "Apache-2.0"
        group.startsWith("io.opencensus") -> "Apache-2.0"
        group.startsWith("io.perfmark") -> "Apache-2.0"
        group.startsWith("org.codehaus.mojo") -> "Apache-2.0"
        group.startsWith("it.unimi.dsi") -> "Apache-2.0"
        group.startsWith("net.java.dev.jna") -> "Apache-2.0 OR LGPL-2.1-or-later"
        group.startsWith("jakarta.activation") -> "EDL-1.0"
        group.startsWith("jakarta.xml.bind") -> "EDL-1.0"
        group.startsWith("org.glassfish.jaxb") -> "EDL-1.0"
        group.startsWith("com.sun.activation") -> "CDDL-1.1 OR GPL-2.0-with-classpath-exception"
        group.startsWith("com.sun.istack") -> "EDL-1.0"
        group.startsWith("com.sun.xml") -> "Apache-2.0"
        group.startsWith("org.jvnet.staxex") -> "CDDL-1.1"
        group.startsWith("org.apache.httpcomponents") -> "Apache-2.0"
        group.startsWith("com.googlecode.juniversalchardet") -> "MPL-1.1 OR LGPL-2.1-or-later"
        group.startsWith("javax.annotation") -> "CDDL-1.1 OR GPL-2.0-with-classpath-exception"
        else -> error("unknown reviewed offline toolchain license group: $group")
    }
}

object NormalizedMavenPom {
    fun render(
        group: String,
        module: String,
        version: String,
        dependencies: List<OfflineMatrixArtifact>,
    ): String = buildString {
        appendLine("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
        appendLine(
            "<project xmlns=\"http://maven.apache.org/POM/4.0.0\" " +
                "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
                "xsi:schemaLocation=\"http://maven.apache.org/POM/4.0.0 " +
                "https://maven.apache.org/xsd/maven-4.0.0.xsd\">",
        )
        appendLine("  <modelVersion>4.0.0</modelVersion>")
        appendLine("  <groupId>${xml(group)}</groupId>")
        appendLine("  <artifactId>${xml(module)}</artifactId>")
        appendLine("  <version>${xml(version)}</version>")
        if (module.endsWith(".gradle.plugin")) appendLine("  <packaging>pom</packaging>")
        appendLine("  <name>Normalized offline component ${xml(group)}:${xml(module)}</name>")
        appendLine("  <dependencies>")
        dependencies.forEach { dependency ->
            appendLine("    <dependency>")
            appendLine("      <groupId>${xml(dependency.group)}</groupId>")
            appendLine("      <artifactId>${xml(dependency.module)}</artifactId>")
            appendLine("      <version>${xml(dependency.version)}</version>")
            dependency.classifier?.let { classifier ->
                appendLine("      <classifier>${xml(classifier)}</classifier>")
            }
            if (dependency.extension != "jar") {
                appendLine("      <type>${xml(dependency.extension)}</type>")
            }
            appendLine("      <scope>runtime</scope>")
            appendLine("    </dependency>")
        }
        appendLine("  </dependencies>")
        appendLine("</project>")
    }

    private fun xml(value: String): String = value
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
}

object GradleDistributionLocator {
    fun findGradleHome(gradleUserHome: Path, version: String): Path {
        val distributions = gradleUserHome.resolve("wrapper/dists/gradle-$version-bin")
        if (Files.isDirectory(distributions)) {
            Files.walk(distributions, 3).use { paths ->
                paths.filter { path ->
                    Files.isDirectory(path) &&
                        path.fileName.toString() == "gradle-$version" &&
                        Files.isRegularFile(path.resolve("bin/gradle"))
                }.sorted().findFirst().orElse(null)
            }?.let { return it }
        }
        val managed = gradleUserHome.resolve("holin-hardening/distributions/$version/gradle-$version")
        if (Files.isDirectory(managed) && Files.isRegularFile(managed.resolve("bin/gradle"))) {
            return managed
        }
        if (Files.exists(distributions) || Files.exists(managed)) {
            throw IllegalStateException("local Gradle $version distribution is incomplete")
        }
        throw IllegalArgumentException("local Gradle $version distribution is unavailable")
    }
}

object OfflineMatrixAssembler {
    fun assemble(
        staging: Path,
        portableExtraction: Path,
        portableArchive: Path,
        pluginVersion: String,
        rows: List<OfflineMatrixInput>,
    ) {
        require(Files.isRegularFile(portableArchive)) { "portable hardening archive is missing: $portableArchive" }
        require(rows.map(OfflineMatrixInput::id).distinct().size == rows.size) {
            "offline matrix row identifiers must be unique"
        }
        deleteTree(staging)
        deleteTree(portableExtraction)
        Files.createDirectories(portableExtraction)
        extract(portableArchive, portableExtraction)
        val portableRepository = portableExtraction.resolve("repository")
        require(Files.isDirectory(portableRepository)) { "extracted portable ZIP repository is missing" }
        val packagedPortable = staging.resolve("portable/${portableArchive.fileName}")
        Files.createDirectories(packagedPortable.parent)
        Files.copy(portableArchive, packagedPortable, REPLACE_EXISTING)
        writeTemplates(staging.resolve("fixture-templates"), pluginVersion)

        val matrixLines = mutableListOf(
            "schema=holin-offline-matrix-v1",
        )
        rows.sortedBy(OfflineMatrixInput::id).forEach { row ->
            assembleRow(staging, portableRepository, row)
            matrixLines += "available|agp=${row.agpVersion}|gradle=${row.gradleVersion}|" +
                "kotlin=${row.kotlinVersion}|aapt2=${row.aapt2Version}|lint=${row.lintVersion}|" +
                "repository=matrix/${row.id}/repository"
        }
        Files.writeString(staging.resolve("MATRIX-MANIFEST.txt"), matrixLines.joinToString("\n", "", "\n"))
        Files.writeString(
            staging.resolve("FIXTURE-MANIFEST.txt"),
            "fixture=generated-inside-test-temp-root\n" +
                "templates=fixture-templates/settings.gradle.template,fixture-templates/build.gradle.template," +
                "fixture-templates/mobile.gradle.template\n" +
                "modules=:mobile,:core,:media\nvariant=demoQa\n" +
                "dependencyVerification=matrix-row-verification-metadata\n" +
                "portableArchive=portable/${portableArchive.fileName}\n" +
                "signing=fixture-only-generated-at-runtime\n",
        )
    }

    private fun assembleRow(staging: Path, portableRepository: Path, row: OfflineMatrixInput) {
        val rowRoot = staging.resolve("matrix/${row.id}")
        val repository = rowRoot.resolve("repository")
        val artifacts = row.artifacts.distinctBy(OfflineMatrixArtifact::coordinate)
            .sortedBy(OfflineMatrixArtifact::coordinate)
        artifacts.forEach { artifact -> copyArtifact(repository, artifact) }
        val concreteComponents = artifacts.mapTo(linkedSetOf(), OfflineMatrixArtifact::componentKey)
        artifacts.distinctBy(OfflineMatrixArtifact::componentKey)
            .sortedBy(OfflineMatrixArtifact::componentKey)
            .forEach { component ->
                val closure = OfflineGraphNormalizer.concreteClosure(
                    row.dependenciesByComponent[component.componentKey].orEmpty(),
                    row.dependenciesByComponent,
                    concreteComponents,
                ).flatMap { dependencyKey ->
                    artifacts.filter { artifact -> artifact.componentKey == dependencyKey }
                }.distinctBy(OfflineMatrixArtifact::coordinate)
                    .sortedBy(OfflineMatrixArtifact::coordinate)
                val directory = artifactDirectory(repository, component)
                Files.writeString(
                    directory.resolve("${component.module}-${component.version}.pom"),
                    NormalizedMavenPom.render(component.group, component.module, component.version, closure),
                )
            }
        writePluginMarkers(repository, row, artifacts)
        Files.writeString(
            rowRoot.resolve("verification-metadata.xml"),
            PortableVerificationMetadata.render(listOf(repository, portableRepository)),
        )
        val inventory = artifacts.map { artifact ->
            "${artifact.coordinate} | ${OfflineLicensePolicy.licenseFor(artifact.group)} | ${sha256(artifact.file)}"
        }.distinct().sorted()
        Files.writeString(
            rowRoot.resolve("THIRD_PARTY_LICENSES.txt"),
            inventory.joinToString(
                "\n",
                "Resolved offline toolchain dependency, license and SHA-256 inventory\n",
                "\n",
            ),
        )
        copyTree(row.gradleHome, rowRoot.resolve("gradle/gradle-${row.gradleVersion}"))
    }

    private fun copyArtifact(repository: Path, artifact: OfflineMatrixArtifact) {
        val directory = artifactDirectory(repository, artifact)
        Files.createDirectories(directory)
        val classifier = artifact.classifier?.let { value -> "-$value" }.orEmpty()
        Files.copy(
            artifact.file,
            directory.resolve("${artifact.module}-${artifact.version}$classifier.${artifact.extension}"),
            REPLACE_EXISTING,
        )
        if (
            artifact.group == "org.jetbrains.kotlin" &&
            artifact.module == "kotlin-gradle-plugin" &&
            artifact.extension == "jar"
        ) {
            Files.copy(
                artifact.file,
                directory.resolve("${artifact.module}-${artifact.version}.jar"),
                REPLACE_EXISTING,
            )
        }
    }

    private fun writePluginMarkers(
        repository: Path,
        row: OfflineMatrixInput,
        artifacts: List<OfflineMatrixArtifact>,
    ) {
        val agpDependency = artifacts.single { artifact ->
            artifact.group == "com.android.tools.build" && artifact.module == "gradle"
        }.withoutClassifier()
        listOf("com.android.application", "com.android.library").forEach { pluginId ->
            val markerDirectory = repository.resolve(pluginId.replace('.', '/'))
                .resolve("$pluginId.gradle.plugin")
                .resolve(row.agpVersion)
            Files.createDirectories(markerDirectory)
            Files.writeString(
                markerDirectory.resolve("$pluginId.gradle.plugin-${row.agpVersion}.pom"),
                NormalizedMavenPom.render(
                    pluginId,
                    "$pluginId.gradle.plugin",
                    row.agpVersion,
                    listOf(agpDependency),
                ),
            )
        }
        val kotlinDependency = artifacts.single { artifact ->
            artifact.group == "org.jetbrains.kotlin" && artifact.module == "kotlin-gradle-plugin"
        }.withoutClassifier()
        val markerDirectory = repository.resolve("org/jetbrains/kotlin/android")
            .resolve("org.jetbrains.kotlin.android.gradle.plugin")
            .resolve(row.kotlinVersion)
        Files.createDirectories(markerDirectory)
        Files.writeString(
            markerDirectory.resolve("org.jetbrains.kotlin.android.gradle.plugin-${row.kotlinVersion}.pom"),
            NormalizedMavenPom.render(
                "org.jetbrains.kotlin.android",
                "org.jetbrains.kotlin.android.gradle.plugin",
                row.kotlinVersion,
                listOf(kotlinDependency),
            ),
        )
    }

    private fun OfflineMatrixArtifact.withoutClassifier(): OfflineMatrixArtifact = OfflineMatrixArtifact(
        group,
        module,
        version,
        null,
        "jar",
        file,
    )

    private fun artifactDirectory(repository: Path, artifact: OfflineMatrixArtifact): Path = repository
        .resolve(artifact.group.replace('.', '/'))
        .resolve(artifact.module)
        .resolve(artifact.version)

    private fun extract(archive: Path, destination: Path) {
        ZipFile(archive.toFile()).use { zip ->
            val names = mutableSetOf<String>()
            zip.entries().asSequence().forEach { entry ->
                require(names.add(entry.name)) { "portable ZIP contains duplicate entry ${entry.name}" }
                val output = destination.resolve(entry.name).normalize()
                require(output.startsWith(destination)) { "portable ZIP entry escapes extraction root" }
                if (entry.isDirectory) {
                    Files.createDirectories(output)
                } else {
                    Files.createDirectories(output.parent)
                    zip.getInputStream(entry).use { input -> Files.copy(input, output, REPLACE_EXISTING) }
                }
            }
        }
    }

    private fun writeTemplates(templates: Path, pluginVersion: String) {
        Files.createDirectories(templates)
        Files.writeString(
            templates.resolve("settings.gradle.template"),
            """
            pluginManagement { repositories { maven { url = uri('@OFFLINE_REPOSITORY@') } } }
            dependencyResolutionManagement {
                repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
                repositories { maven { url = uri('@OFFLINE_REPOSITORY@') } }
            }
            rootProject.name = 'portable-hardening-consumer'
            include ':mobile', ':core', ':media'
            """.trimIndent() + "\n",
        )
        Files.writeString(
            templates.resolve("build.gradle.template"),
            """
            plugins {
                id 'com.android.application' version '@AGP_VERSION@' apply false
                id 'com.android.library' version '@AGP_VERSION@' apply false
                id 'org.jetbrains.kotlin.android' version '@KOTLIN_VERSION@' apply false
                id 'com.holin.android.hardening' version '$pluginVersion' apply false
            }
            """.trimIndent() + "\n",
        )
        Files.writeString(
            templates.resolve("mobile.gradle.template"),
            """
            plugins {
                id 'com.android.application'
                id 'org.jetbrains.kotlin.android'
                id 'com.holin.android.hardening'
            }
            androidHardening {
                enabled.set(true)
                projectKey.set('@PROJECT_KEY@')
                variants.include('@VARIANT@')
            }
            // Supply signing material only from the generated fixture temp root.
            @SIGNING_CONFIG@
            """.trimIndent() + "\n",
        )
    }

    private fun copyTree(source: Path, destination: Path) {
        require(Files.isDirectory(source)) { "Gradle home is missing: $source" }
        Files.walk(source).use { paths ->
            paths.sorted().forEach { path ->
                val target = destination.resolve(source.relativize(path).toString())
                if (Files.isDirectory(path)) {
                    Files.createDirectories(target)
                } else if (Files.isRegularFile(path)) {
                    Files.createDirectories(target.parent)
                    Files.copy(path, target, REPLACE_EXISTING)
                }
            }
        }
    }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { paths ->
            paths.sorted(Comparator.reverseOrder()).forEach(Files::delete)
        }
    }

    private fun sha256(path: Path): String = Files.newInputStream(path).use { input ->
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            digest.update(buffer, 0, count)
        }
        digest.digest().joinToString("") { byte -> "%02x".format(byte) }
    }
}
