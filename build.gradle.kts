import com.holin.buildsupport.ArchiveChecksumCoverage
import com.holin.buildsupport.GradleDistributionProvisioner
import com.holin.buildsupport.HardeningEnvironmentSnapshot
import com.holin.buildsupport.HardeningEnvironmentValidator
import com.holin.buildsupport.OfflineMatrixArtifact
import com.holin.buildsupport.OfflineMatrixAssembler
import com.holin.buildsupport.OfflineMatrixInput
import com.holin.buildsupport.OfflineMatrixPreparation
import com.holin.buildsupport.OfflineGraphNormalizer
import com.holin.buildsupport.OfflineTestKitEnvironmentContract
import com.holin.buildsupport.OfflineTestKitEnvironmentPreparer
import com.holin.buildsupport.PortableVerificationMetadata
import com.holin.buildsupport.RecursiveArchiveSensitivityScanner
import java.io.InputStream
import java.security.MessageDigest
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.util.Locale
import java.util.zip.ZipFile
import javax.xml.parsers.DocumentBuilderFactory
import groovy.util.Node
import org.gradle.api.artifacts.ResolvedDependency
import org.gradle.api.artifacts.component.ModuleComponentIdentifier
import org.gradle.api.artifacts.result.ResolvedArtifactResult
import org.gradle.api.attributes.plugin.GradlePluginApiVersion
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.api.publish.tasks.GenerateModuleMetadata
import org.gradle.api.tasks.testing.Test
import org.gradle.api.tasks.bundling.AbstractArchiveTask
import org.gradle.api.tasks.bundling.Zip
import org.gradle.maven.MavenModule
import org.gradle.maven.MavenPomArtifact
import org.gradle.util.GradleVersion

plugins {
    `kotlin-dsl`
    `java-gradle-plugin`
    `maven-publish`
}

data class PortableRuntimeArtifact(
    val group: String,
    val module: String,
    val version: String,
    val classifier: String?,
    val extension: String,
    val file: File,
    val componentId: ModuleComponentIdentifier,
) {
    val coordinate: String = buildString {
        append("$group:$module:$version")
        classifier?.let { append(":$it") }
        if (extension != "jar") append("@$extension")
    }
}

data class OfflineMatrixRow(
    val id: String,
    val agpVersion: String,
    val gradleVersion: String,
    val kotlinVersion: String,
    val aapt2Version: String,
    val lintVersion: String,
    val configurationName: String,
)

fun sha256(input: InputStream): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
    while (true) {
        val count = input.read(buffer)
        if (count < 0) break
        digest.update(buffer, 0, count)
    }
    return digest.digest().joinToString("") { byte -> "%02x".format(byte) }
}

fun sha256(path: Path): String = Files.newInputStream(path).use(::sha256)

fun dependencyVerificationMetadata(vararg repositories: Path): String =
    PortableVerificationMetadata.render(repositories.asList())

fun normalizedConcreteDependencyClosure(
    roots: Collection<String>,
    dependencies: Map<String, Set<String>>,
    concreteComponents: Set<String>,
): List<String> {
    return OfflineGraphNormalizer.concreteClosure(roots, dependencies, concreteComponents)
}

group = "com.holin.android.hardening"
version = "1.3.0"

base {
    archivesName.set("hardening-gradle-plugin")
}

java {
    withSourcesJar()
    withJavadocJar()
}

tasks.named<AbstractArchiveTask>("sourcesJar") {
    includeEmptyDirs = false
}

val aapt2TestHost = when {
    System.getProperty("os.name").lowercase().contains("mac") -> "osx"
    System.getProperty("os.name").lowercase().contains("win") -> "windows"
    else -> "linux"
}

repositories {
    google()
    mavenCentral()
    gradlePluginPortal()
}

dependencies {
    compileOnly("com.android.tools.build:gradle-api:8.8.0")
    implementation("com.android.tools.build:aapt2-proto:8.13.2-14304508")
    implementation("com.google.protobuf:protobuf-java:3.25.5")
    compileOnly("com.android.tools.build:builder:8.8.0") {
        because("Compile against the minimum supported public AGP API; the consumer supplies its compatible runtime")
    }
    implementation("com.android.tools.build:bundletool:1.18.1")
    implementation("com.android.tools.smali:smali-dexlib2:3.0.9")
    runtimeOnly("com.github.usefulness:webp-imageio:0.10.2") {
        // The ImageIO SPI is consumed only through javax.imageio. Keeping the
        // Kotlin 2.2 implementation off kotlin-dsl's compile classpath avoids
        // exposing metadata newer than Gradle 8.13's embedded compiler.
        exclude("org.jetbrains.kotlin", "kotlin-stdlib")
    }
    implementation("org.ow2.asm:asm:9.8")
    implementation("org.ow2.asm:asm-commons:9.8")
    implementation("org.ow2.asm:asm-tree:9.8")

    testImplementation(gradleTestKit())
    // The real-AGP TestKit fixture runs offline against this build's shared cache.
    // Resolve the complete plugin graph here so the nested build never depends on
    // an incidental developer-machine cache or a network connection.
    testImplementation("com.android.tools.build:gradle:8.13.2")
    testImplementation("com.android.tools.build:builder:8.13.2")
    testImplementation("org.jetbrains.kotlin:kotlin-gradle-plugin:2.3.0")
    testImplementation("com.google.code.gson:gson:2.13.2")
    testImplementation("org.snakeyaml:snakeyaml-engine:2.9")
    testImplementation(kotlin("test-junit5"))
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    // Real offline AGP fixtures need the host AAPT2 executable as well as the
    // plugin graph warmed by testImplementation above.
    testRuntimeOnly("com.android.tools.build:aapt2:8.13.2-14304508:$aapt2TestHost")
}

val offlineMatrixRows = listOf(
    OfflineMatrixRow("agp-8.8.0", "8.8.0", "8.10.2", "2.3.0", "8.8.0-12006047", "31.8.0", "offlineMatrixAgp880"),
    OfflineMatrixRow("agp-8.10.1", "8.10.1", "8.11.1", "2.3.0", "8.10.1-12782657", "31.10.1", "offlineMatrixAgp8101"),
    OfflineMatrixRow("agp-8.13.2", "8.13.2", "8.13", "2.3.0", "8.13.2-14304508", "31.13.2", "offlineMatrixAgp8132"),
)
offlineMatrixRows.forEach { row ->
    configurations.create(row.configurationName) {
        isCanBeConsumed = false
        isCanBeResolved = true
        attributes.attribute(
            GradlePluginApiVersion.GRADLE_PLUGIN_API_VERSION_ATTRIBUTE,
            objects.named(row.gradleVersion),
        )
    }
    dependencies.add(row.configurationName, "com.android.tools.build:gradle:${row.agpVersion}")
    dependencies.add(row.configurationName, "org.jetbrains.kotlin:kotlin-gradle-plugin:${row.kotlinVersion}")
    dependencies.add(row.configurationName, "org.jetbrains.kotlin:kotlin-stdlib:${row.kotlinVersion}")
    dependencies.add(row.configurationName, "org.jetbrains.kotlin:kotlin-build-tools-compat:${row.kotlinVersion}")
    dependencies.add(row.configurationName, "org.jetbrains.kotlin:kotlin-build-tools-impl:${row.kotlinVersion}")
    dependencies.add(row.configurationName, "com.android.tools.build:aapt2:${row.aapt2Version}:$aapt2TestHost")
    dependencies.add(row.configurationName, "com.android.tools.lint:lint-gradle:${row.lintVersion}")
}

val checkHardeningEnvironment = tasks.register("checkHardeningEnvironment") {
    group = "verification"
    description = "Checks the Gradle, JDK, and Android SDK prerequisites without modifying them."
    doLast {
        val androidSdk = listOf("ANDROID_SDK_ROOT", "ANDROID_HOME")
            .asSequence()
            .mapNotNull(System::getenv)
            .map(String::trim)
            .filter(String::isNotEmpty)
            .map(Path::of)
            .firstOrNull()
        HardeningEnvironmentValidator.requireValid(
            HardeningEnvironmentSnapshot(
                GradleVersion.current().version,
                Runtime.version().feature(),
                androidSdk,
            ),
        )
    }
}

val preparedOfflineGradleHomes = linkedMapOf<String, Path>()
val prepareOfflineTestKitEnvironment = tasks.register("prepareOfflineTestKitEnvironment") {
    group = "build setup"
    description = "Prepares checksum-pinned Gradle distributions and warms every offline TestKit matrix row."
    doLast {
        val rows = offlineMatrixRows.map { row ->
            OfflineMatrixPreparation(row.id) {
                configurations[row.configurationName].resolvedConfiguration.resolvedArtifacts
                    .forEach { artifact -> require(artifact.file.isFile) }
            }
        }
        val prepared = OfflineTestKitEnvironmentPreparer(GradleDistributionProvisioner()).prepare(
            gradle.gradleUserHomeDir.toPath(),
            OfflineTestKitEnvironmentContract.gradleDistributions,
            rows,
            gradle.startParameter.isOffline,
        )
        preparedOfflineGradleHomes.clear()
        preparedOfflineGradleHomes.putAll(prepared.gradleHomes)
    }
}

tasks.register("testOfflineResolvedGraphNormalization") {
    group = "verification"
    description = "Checks metadata-only graph flattening, cycle rejection, and deterministic ordering."
    doLast {
        val firstGraph = linkedMapOf(
            "metadata-a" to linkedSetOf("metadata-b"),
            "metadata-b" to linkedSetOf("artifact-a"),
        )
        val secondGraph = linkedMapOf(
            "metadata-b" to linkedSetOf("artifact-a"),
            "metadata-a" to linkedSetOf("metadata-b"),
        )
        val first = normalizedConcreteDependencyClosure(
            linkedSetOf("metadata-a", "artifact-b"),
            firstGraph,
            setOf("artifact-a", "artifact-b"),
        )
        val deterministicFirst = normalizedConcreteDependencyClosure(
            linkedSetOf("artifact-b", "artifact-a"),
            firstGraph,
            linkedSetOf("artifact-a", "artifact-b"),
        )
        val deterministicSecond = normalizedConcreteDependencyClosure(
            linkedSetOf("artifact-a", "artifact-b"),
            secondGraph,
            linkedSetOf("artifact-b", "artifact-a"),
        )
        val cycle = runCatching {
            normalizedConcreteDependencyClosure(
                listOf("metadata-a"),
                mapOf("metadata-a" to setOf("metadata-b"), "metadata-b" to setOf("metadata-a")),
                emptySet(),
            )
        }
        val issues = buildList {
            if (first != listOf("artifact-a", "artifact-b")) add("metadata-only multi-level nodes were not flattened")
            if (cycle.isSuccess) add("metadata-only dependency cycle was not rejected")
            if (deterministicFirst != deterministicSecond) add("normalized dependency order depends on input insertion order")
        }
        check(issues.isEmpty()) { issues.joinToString("; ") }
    }
}

val functionalTest = sourceSets.create("functionalTest")
configurations[functionalTest.implementationConfigurationName].extendsFrom(configurations.testImplementation.get())
configurations[functionalTest.runtimeOnlyConfigurationName].extendsFrom(configurations.testRuntimeOnly.get())
dependencies {
    add(functionalTest.implementationConfigurationName, sourceSets.main.get().output)
    add(functionalTest.implementationConfigurationName, "org.bouncycastle:bcpkix-jdk18on:1.79")
}

gradlePlugin {
    plugins {
        create("androidHardening") {
            id = "com.holin.android.hardening"
            implementationClass = "com.holin.android.hardening.AndroidHardeningPlugin"
        }
    }
    testSourceSets(functionalTest)
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

tasks.withType<AbstractArchiveTask>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}

tasks.jar {
    from(layout.projectDirectory.file("LICENSE")) {
        into("META-INF")
    }
    from(layout.projectDirectory.file("NOTICE")) {
        into("META-INF")
    }
    manifest.attributes["Implementation-Version"] = project.version.toString()
}

val functionalTestTask = tasks.register<Test>("functionalTest") {
    group = "verification"
    description = "Runs Gradle TestKit functional tests."
    testClassesDirs = functionalTest.output.classesDirs
    classpath = functionalTest.runtimeClasspath
    useJUnitPlatform()
    shouldRunAfter(tasks.test)
}

tasks.check {
    dependsOn(functionalTestTask)
}

val portableRepository = layout.buildDirectory.dir("portable/repository")
val portableRuntimeRepository = layout.buildDirectory.dir("portable/runtime-repository")
val portableRuntimeMetadata = layout.buildDirectory.dir("portable/runtime-metadata")
val portableStaging = layout.buildDirectory.dir("portable/staging")
val portableArchive = layout.buildDirectory.file(
    "distributions/hardening-gradle-plugin-${project.version}-portable-maven.zip",
)
val portableArchiveChecksum = layout.buildDirectory.file(
    "distributions/hardening-gradle-plugin-${project.version}-portable-maven.zip.sha256",
)
val offlineTestKitStaging = layout.buildDirectory.dir("offline-testkit/staging")
val offlineTestKitArchive = layout.buildDirectory.file(
    "distributions/hardening-gradle-plugin-${project.version}-offline-testkit.zip",
)
val portableRuntimeArtifacts = providers.provider {
    configurations.runtimeClasspath.get().resolvedConfiguration.resolvedArtifacts
        .mapNotNull { artifact ->
            val id = artifact.moduleVersion.id
            val componentId = artifact.id.componentIdentifier as? ModuleComponentIdentifier
                ?: return@mapNotNull null
            val consumerProvided =
                (id.group == "com.android.tools.build" && id.name in setOf("gradle", "gradle-api", "builder")) ||
                    id.group.startsWith("org.jetbrains.kotlin")
            if (consumerProvided) {
                null
            } else {
                PortableRuntimeArtifact(
                    id.group,
                    id.name,
                    id.version,
                    artifact.classifier,
                    artifact.extension ?: "jar",
                    artifact.file,
                    componentId,
                )
            }
        }
        .distinctBy { artifact -> artifact.coordinate }
        .sortedBy(PortableRuntimeArtifact::coordinate)
}

publishing {
    publications.withType<MavenPublication>().configureEach {
        if (name == "pluginMaven") {
            artifactId = "hardening-gradle-plugin"
            pom.withXml {
                val root = asNode()
                root.children()
                    .filterIsInstance<Node>()
                    .filter { child -> child.name().toString().endsWith("dependencies") }
                    .forEach(root::remove)
                val dependencies = root.appendNode("dependencies")
                portableRuntimeArtifacts.get().forEach { artifact ->
                    val dependency = dependencies.appendNode("dependency")
                    dependency.appendNode("groupId", artifact.group)
                    dependency.appendNode("artifactId", artifact.module)
                    dependency.appendNode("version", artifact.version)
                    dependency.appendNode("scope", "runtime")
                    artifact.classifier?.let { dependency.appendNode("classifier", it) }
                    if (artifact.extension != "jar") dependency.appendNode("type", artifact.extension)
                    val exclusions = dependency.appendNode("exclusions")
                    val exclusion = exclusions.appendNode("exclusion")
                    exclusion.appendNode("groupId", "*")
                    exclusion.appendNode("artifactId", "*")
                }
            }
        }
        pom {
            name.set("Holin Android Hardening Gradle Plugin")
            description.set("Local artifact hardening for Android Application variants.")
            licenses {
                license {
                    name.set("The Apache License, Version 2.0")
                    url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    distribution.set("repo")
                }
            }
        }
    }
    repositories {
        maven {
            name = "Portable"
            url = uri(portableRepository)
        }
    }
}

// Maven POM is the portable consumer contract. Avoid publishing Gradle metadata
// whose dependency variants can differ across Gradle patch releases.
tasks.withType<GenerateModuleMetadata>().configureEach {
    enabled = false
}

val populatePortableRuntimeRepository = tasks.register("populatePortableRuntimeRepository") {
    val runtimeRepository = portableRuntimeRepository
    val thirdPartyLicenses = portableRuntimeMetadata.map { it.file("THIRD_PARTY_LICENSES.txt") }
    inputs.files(configurations.runtimeClasspath)
    outputs.dir(runtimeRepository)
    outputs.file(thirdPartyLicenses)
    doLast {
        val artifacts = portableRuntimeArtifacts.get()
        val componentIds = artifacts.map(PortableRuntimeArtifact::componentId).distinct()
        val pomByComponent = dependencies.createArtifactResolutionQuery()
            .forComponents(componentIds)
            .withArtifacts(MavenModule::class.java, MavenPomArtifact::class.java)
            .execute()
            .resolvedComponents
            .associate { component ->
                component.id to component.getArtifacts(MavenPomArtifact::class.java)
                    .filterIsInstance<ResolvedArtifactResult>()
                    .singleOrNull()
                    ?.file
            }
        fun fallbackLicenses(artifact: PortableRuntimeArtifact): List<String> = when {
            artifact.group == "com.google.protobuf" -> listOf("BSD-3-Clause")
            artifact.group.startsWith("com.google.") -> listOf("Apache-2.0")
            artifact.group.startsWith("com.android.tools") -> listOf("Apache-2.0")
            artifact.group.startsWith("com.github.usefulness") -> listOf("Apache-2.0")
            artifact.group.startsWith("javax.inject") -> listOf("Apache-2.0")
            artifact.group.startsWith("org.bitbucket.b_c") -> listOf("Apache-2.0")
            artifact.group.startsWith("org.checkerframework") -> listOf("MIT")
            artifact.group.startsWith("org.ow2.asm") -> listOf("BSD-3-Clause")
            artifact.group == "org.slf4j" -> listOf("MIT")
            else -> error("unknown reviewed portable runtime license for ${artifact.coordinate}")
        }
        fun licensesFor(pom: File, artifact: PortableRuntimeArtifact): List<String> {
            require(pom.isFile) { "upstream Maven POM is not a file for ${artifact.coordinate}: $pom" }
            val factory = DocumentBuilderFactory.newInstance().apply {
                setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
                isExpandEntityReferences = false
            }
            val document = factory.newDocumentBuilder().parse(pom)
            val licenses = document.getElementsByTagName("license")
            return (0 until licenses.length).mapNotNull { index ->
                val children = licenses.item(index).childNodes
                (0 until children.length)
                    .map(children::item)
                    .firstOrNull { child -> child.nodeName == "name" }
                    ?.textContent
                    ?.trim()
                    ?.takeIf(String::isNotEmpty)
            }.distinct().sorted().ifEmpty { fallbackLicenses(artifact) }
        }
        val repository = runtimeRepository.get().asFile.toPath()
        project.delete(repository.toFile())
        val licenseLines = artifacts.map { artifact ->
            val directory = repository
                .resolve(artifact.group.replace('.', '/'))
                .resolve(artifact.module)
                .resolve(artifact.version)
            Files.createDirectories(directory)
            val classifier = artifact.classifier?.let { "-$it" }.orEmpty()
            val artifactName = "${artifact.module}-${artifact.version}$classifier.${artifact.extension}"
            Files.copy(artifact.file.toPath(), directory.resolve(artifactName), REPLACE_EXISTING)
            val pom = pomByComponent[artifact.componentId]
            val licenses = if (pom == null) fallbackLicenses(artifact) else licensesFor(pom, artifact)
            val pomName = "${artifact.module}-${artifact.version}.pom"
            Files.writeString(
                directory.resolve(pomName),
                buildString {
                    appendLine("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
                    appendLine("<project xmlns=\"http://maven.apache.org/POM/4.0.0\">")
                    appendLine("  <modelVersion>4.0.0</modelVersion>")
                    appendLine("  <groupId>${artifact.group}</groupId>")
                    appendLine("  <artifactId>${artifact.module}</artifactId>")
                    appendLine("  <version>${artifact.version}</version>")
                    appendLine("  <name>Normalized portable runtime ${artifact.group}:${artifact.module}</name>")
                    appendLine("</project>")
                },
            )
            "${artifact.coordinate} | ${licenses.joinToString()}"
        }.distinct().sorted()
        val licenseFile = thirdPartyLicenses.get().asFile.toPath()
        Files.createDirectories(licenseFile.parent)
        Files.writeString(
            licenseFile,
            buildString {
                appendLine("Third-party runtime dependency and license inventory")
                appendLine("Generated from the resolved portable runtime closure.")
                appendLine()
                licenseLines.forEach(::appendLine)
            },
        )
    }
}

val stagePortableHardeningRepository = tasks.register<Sync>("stagePortableHardeningRepository") {
    dependsOn("publishAllPublicationsToPortableRepository", populatePortableRuntimeRepository)
    from(portableRepository) {
        into("repository")
        exclude("**/maven-metadata.xml*")
        include("com/holin/android/hardening/hardening-gradle-plugin/${project.version}/**")
        include("com/holin/android/hardening/com.holin.android.hardening.gradle.plugin/${project.version}/**")
    }
    from(layout.projectDirectory.file("LICENSE"))
    from(layout.projectDirectory.file("NOTICE"))
    from(portableRuntimeRepository) {
        into("repository")
    }
    from(portableRuntimeMetadata.map { it.file("THIRD_PARTY_LICENSES.txt") })
    into(portableStaging)
    doLast {
        val staging = portableStaging.get().asFile.toPath()
        val hasLegacyIdentity = Files.walk(staging).use { paths ->
            paths.iterator().asSequence().any { path ->
                val name = staging.relativize(path).toString().replace('\\', '/')
                name.lowercase(Locale.ROOT).contains("/android/hardening/") &&
                    !name.startsWith("repository/com/holin/android/hardening/")
            }
        }
        require(!hasLegacyIdentity) { "portable staging contains a legacy hardening identity" }
        Files.writeString(
            staging.resolve("verification-metadata.xml"),
            dependencyVerificationMetadata(staging.resolve("repository")),
        )
    }
}

val generatePortableHardeningChecksums = tasks.register("generatePortableHardeningChecksums") {
    dependsOn(stagePortableHardeningRepository)
    val checksumFile = portableStaging.map { it.file("SHA256SUMS") }
    outputs.file(checksumFile)
    doLast {
        val staging = portableStaging.get().asFile.toPath()
        val entries = Files.walk(staging).use { paths ->
            paths.filter { path -> Files.isRegularFile(path) }
                .filter { it.fileName.toString() != "SHA256SUMS" }
                .map { file ->
                    val digest = MessageDigest.getInstance("SHA-256")
                        .digest(Files.readAllBytes(file))
                        .joinToString("") { byte -> "%02x".format(byte) }
                    "$digest  ${staging.relativize(file).toString().replace('\\', '/')}"
                }
                .sorted()
                .toList()
        }
        Files.writeString(
            checksumFile.get().asFile.toPath(),
            entries.joinToString("\n", "", "\n"),
        )
    }
}

val packagePortableHardeningPlugin = tasks.register<Zip>("packagePortableHardeningPlugin") {
    group = "distribution"
    description = "Packages the local Maven hardening plugin repository as a deterministic ZIP."
    dependsOn(generatePortableHardeningChecksums)
    from(portableStaging)
    archiveFileName.set(portableArchive.map { it.asFile.name })
    destinationDirectory.set(layout.buildDirectory.dir("distributions"))
    outputs.file(portableArchiveChecksum)
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
    doLast {
        val archive = portableArchive.get().asFile.toPath()
        val checksum = portableArchiveChecksum.get().asFile.toPath()
        Files.createDirectories(requireNotNull(checksum.parent))
        Files.writeString(checksum, "${sha256(archive)}  ${archive.fileName}\n")
    }
}

val stageOfflineHardeningTestKit = tasks.register("stageOfflineHardeningTestKit") {
    dependsOn(packagePortableHardeningPlugin, prepareOfflineTestKitEnvironment)
    inputs.file(portableArchive)
    offlineMatrixRows.forEach { row -> inputs.files(configurations[row.configurationName]) }
    outputs.dir(offlineTestKitStaging)
    doLast {
        fun componentKey(group: String, module: String, version: String): String = "$group:$module:$version"

        val matrixInputs = offlineMatrixRows.map { row ->
            val resolvedConfiguration = configurations[row.configurationName].resolvedConfiguration
            val artifacts = resolvedConfiguration.resolvedArtifacts
                .mapNotNull { artifact ->
                    val id = artifact.moduleVersion.id
                    artifact.id.componentIdentifier as? ModuleComponentIdentifier
                        ?: return@mapNotNull null
                    OfflineMatrixArtifact(
                        id.group,
                        id.name,
                        id.version,
                        artifact.classifier,
                        artifact.extension ?: "jar",
                        artifact.file.toPath(),
                    )
                }
                .distinctBy(OfflineMatrixArtifact::coordinate)
                .sortedBy(OfflineMatrixArtifact::coordinate)
            val dependenciesByComponent = linkedMapOf<String, MutableSet<String>>()
            val visitedComponents = mutableSetOf<String>()
            fun collectDependencies(dependency: ResolvedDependency) {
                val key = componentKey(
                    dependency.moduleGroup,
                    dependency.moduleName,
                    dependency.moduleVersion,
                )
                val children = dependency.children.sortedBy { child ->
                    componentKey(child.moduleGroup, child.moduleName, child.moduleVersion)
                }
                dependenciesByComponent.getOrPut(key, ::linkedSetOf).addAll(
                    children.map { child ->
                        componentKey(child.moduleGroup, child.moduleName, child.moduleVersion)
                    },
                )
                if (!visitedComponents.add(key)) return
                children.forEach(::collectDependencies)
            }
            resolvedConfiguration.firstLevelModuleDependencies
                .sortedBy { dependency ->
                    componentKey(
                        dependency.moduleGroup,
                        dependency.moduleName,
                        dependency.moduleVersion,
                    )
                }
                .forEach(::collectDependencies)
            OfflineMatrixInput(
                row.id,
                row.agpVersion,
                row.gradleVersion,
                row.kotlinVersion,
                row.aapt2Version,
                row.lintVersion,
                checkNotNull(preparedOfflineGradleHomes[row.gradleVersion]) {
                    "prepared Gradle ${row.gradleVersion} home is unavailable"
                },
                artifacts,
                dependenciesByComponent.mapValues { (_, dependencies) -> dependencies.toSet() },
            )
        }
        OfflineMatrixAssembler.assemble(
            offlineTestKitStaging.get().asFile.toPath(),
            layout.buildDirectory.dir("offline-testkit/portable-extracted").get().asFile.toPath(),
            portableArchive.get().asFile.toPath(),
            project.version.toString(),
            matrixInputs,
        )
    }
}
val generateOfflineHardeningTestKitChecksums = tasks.register("generateOfflineHardeningTestKitChecksums") {
    dependsOn(stageOfflineHardeningTestKit)
    val checksumFile = offlineTestKitStaging.map { it.file("SHA256SUMS") }
    outputs.file(checksumFile)
    doLast {
        val staging = offlineTestKitStaging.get().asFile.toPath()
        val entries = Files.walk(staging).use { paths ->
            paths.filter(Files::isRegularFile)
                .filter { path -> path.fileName.toString() != "SHA256SUMS" }
                .map { file ->
                    "${sha256(file)}  ${staging.relativize(file).toString().replace('\\', '/')}"
                }
                .sorted()
                .toList()
        }
        Files.writeString(checksumFile.get().asFile.toPath(), entries.joinToString("\n", "", "\n"))
    }
}

val packageOfflineHardeningTestKit = tasks.register<Zip>("packageOfflineHardeningTestKit") {
    group = "distribution"
    description = "Packages the true offline TestKit matrix and normalized local Maven repositories."
    dependsOn(generateOfflineHardeningTestKitChecksums)
    from(offlineTestKitStaging)
    archiveFileName.set(offlineTestKitArchive.map { it.asFile.name })
    destinationDirectory.set(layout.buildDirectory.dir("distributions"))
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}

functionalTestTask.configure {
    dependsOn(packagePortableHardeningPlugin, packageOfflineHardeningTestKit)
    systemProperty("portable.plugin.archive", portableArchive.get().asFile.absolutePath)
    systemProperty("portable.offline.testkit.archive", offlineTestKitArchive.get().asFile.absolutePath)
    systemProperty("portable.gradle.user.home", gradle.gradleUserHomeDir.absolutePath)
}

tasks.register("verifyPortableHardeningPlugin") {
    group = "verification"
    description = "Verifies the portable Maven ZIP layout, checksums, and sensitive-path exclusions."
    dependsOn(packagePortableHardeningPlugin)
    inputs.file(portableArchive)
    inputs.file(portableArchiveChecksum)
    doLast {
        val archive = portableArchive.get().asFile
        require(archive.isFile) { "portable hardening archive is missing: $archive" }
        val checksum = portableArchiveChecksum.get().asFile
        require(checksum.isFile) { "portable hardening archive checksum is missing: $checksum" }
        val expectedChecksum = "${sha256(archive.toPath())}  ${archive.name}\n"
        val actualChecksum = Files.readString(checksum.toPath())
        require(actualChecksum == expectedChecksum) { "portable hardening archive checksum mismatch" }
        ZipFile(archive).use { zip ->
            val entries = zip.entries().asSequence().filterNot { it.isDirectory }.toList()
            val names = entries.map { it.name }
            require(names.distinct().size == names.size) { "portable hardening ZIP contains duplicate entries" }
            val version = project.version.toString()
            val implementationRoot =
                "repository/com/holin/android/hardening/hardening-gradle-plugin/$version/"
            val markerRoot =
                "repository/com/holin/android/hardening/com.holin.android.hardening.gradle.plugin/$version/"
            listOf(
                "LICENSE",
                "NOTICE",
                "THIRD_PARTY_LICENSES.txt",
                "verification-metadata.xml",
                "SHA256SUMS",
                "${implementationRoot}hardening-gradle-plugin-$version.jar",
                "${implementationRoot}hardening-gradle-plugin-$version.pom",
                "${implementationRoot}hardening-gradle-plugin-$version-sources.jar",
                "${implementationRoot}hardening-gradle-plugin-$version-javadoc.jar",
                "${markerRoot}com.holin.android.hardening.gradle.plugin-$version.pom",
            ).forEach { required -> require(required in names) { "portable ZIP is missing $required" } }
            listOf(
                "com/android/tools/build/aapt2-proto/8.13.2-14304508/aapt2-proto-8.13.2-14304508.jar",
                "com/android/tools/build/bundletool/1.18.1/bundletool-1.18.1.jar",
                "com/android/tools/smali/smali-dexlib2/3.0.9/smali-dexlib2-3.0.9.jar",
                "com/github/usefulness/webp-imageio/0.10.2/webp-imageio-0.10.2.jar",
                "org/ow2/asm/asm/9.8/asm-9.8.jar",
            ).forEach { dependency ->
                require("repository/$dependency" in names) { "portable ZIP is missing runtime $dependency" }
            }
            val implementationPomPath =
                "${implementationRoot}hardening-gradle-plugin-$version.pom"
            val implementationPomEntry = requireNotNull(zip.getEntry(implementationPomPath)) {
                "portable ZIP is missing normalized implementation POM"
            }
            val implementationPom = zip.getInputStream(implementationPomEntry).use { input ->
                DocumentBuilderFactory.newInstance().apply {
                    setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
                    isExpandEntityReferences = false
                }.newDocumentBuilder().parse(input)
            }
            val implementationDependencies = implementationPom.getElementsByTagName("dependency")
            val hasDaggerDependency = (0 until implementationDependencies.length).any { index ->
                val children = implementationDependencies.item(index).childNodes
                val values = (0 until children.length)
                    .map(children::item)
                    .associate { child -> child.nodeName to child.textContent.trim() }
                values["groupId"] == "com.google.dagger" && values["artifactId"] == "dagger"
            }
            require(hasDaggerDependency) {
                "normalized implementation POM must declare the resolved Dagger closure"
            }
            require(names.none { name ->
                name.startsWith("repository/com/android/tools/build/gradle/") ||
                    name.startsWith("repository/com/android/tools/build/builder/") ||
                    name.startsWith("repository/org/jetbrains/kotlin/")
            }) { "portable ZIP must not carry AGP or Kotlin plugin/runtime components" }
            require(names.none { name ->
                name.lowercase(Locale.ROOT).contains("/android/hardening/") &&
                    !name.startsWith("repository/com/holin/android/hardening/")
            }) {
                "portable ZIP contains a legacy hardening identity"
            }
            val forbidden = listOf(
                ".jks", ".keystore", ".hardening/", "mapping.txt", "baseline.json",
                "gradle.properties", ".gradle/", ".gradle-home/", "/build/outputs/",
            )
            require(names.none { name -> forbidden.any(name::contains) }) {
                "portable ZIP contains a forbidden path"
            }
            val checksums = zip.getInputStream(zip.getEntry("SHA256SUMS"))
                .bufferedReader()
                .readLines()
                .filter(String::isNotBlank)
            ArchiveChecksumCoverage.requireExhaustive(
                names,
                checksums.map { line -> line.substringAfter("  ") },
            )
            checksums.forEach { line ->
                val expected = line.substringBefore("  ")
                val path = line.substringAfter("  ")
                val entry = requireNotNull(zip.getEntry(path)) { "checksum references missing entry $path" }
                val actual = MessageDigest.getInstance("SHA-256")
                    .digest(zip.getInputStream(entry).readBytes())
                    .joinToString("") { byte -> "%02x".format(byte) }
                require(expected == actual) { "checksum mismatch for $path" }
            }
            val thirdPartyLicenses = zip.getInputStream(zip.getEntry("THIRD_PARTY_LICENSES.txt"))
                .bufferedReader()
                .readText()
            require("UNKNOWN" !in thirdPartyLicenses) {
                "portable runtime license inventory contains unresolved licenses"
            }
            val verificationMetadata = zip.getInputStream(zip.getEntry("verification-metadata.xml"))
                .bufferedReader()
                .readText()
            require("<verify-metadata>true</verify-metadata>" in verificationMetadata) {
                "portable dependency verification metadata is disabled"
            }
            require(
                "group=\"com.holin.android.hardening\" name=\"hardening-gradle-plugin\" " +
                    "version=\"${project.version}\"" in verificationMetadata,
            ) { "portable dependency verification metadata is missing the implementation artifact" }
        }
        RecursiveArchiveSensitivityScanner.verify(archive.toPath())
    }
}

tasks.register("verifyOfflineHardeningTestKit") {
    group = "verification"
    description = "Verifies offline TestKit templates, dependency metadata, checksums, and sensitive-path exclusions."
    dependsOn(packageOfflineHardeningTestKit)
    inputs.file(offlineTestKitArchive)
    doLast {
        val archive = offlineTestKitArchive.get().asFile
        require(archive.isFile) { "offline hardening TestKit archive is missing: $archive" }
        ZipFile(archive).use { zip ->
            val entries = zip.entries().asSequence().filterNot { entry -> entry.isDirectory }.toList()
            val names = entries.map { entry -> entry.name }
            require(names.distinct().size == names.size) { "offline TestKit ZIP contains duplicate entries" }
            val required = listOf(
                "SHA256SUMS",
                "MATRIX-MANIFEST.txt",
                "FIXTURE-MANIFEST.txt",
                "portable/${portableArchive.get().asFile.name}",
                "fixture-templates/settings.gradle.template",
                "fixture-templates/build.gradle.template",
                "fixture-templates/mobile.gradle.template",
                "matrix/agp-8.8.0/verification-metadata.xml",
                "matrix/agp-8.10.1/verification-metadata.xml",
                "matrix/agp-8.13.2/verification-metadata.xml",
            )
            required.forEach { name -> require(name in names) { "offline TestKit ZIP is missing $name" } }
            val manifest = zip.getInputStream(zip.getEntry("MATRIX-MANIFEST.txt"))
                .bufferedReader()
                .readLines()
            offlineMatrixRows.forEach { row ->
                require(
                    manifest.any { line ->
                        line == "available|agp=${row.agpVersion}|gradle=${row.gradleVersion}|" +
                            "kotlin=${row.kotlinVersion}|aapt2=${row.aapt2Version}|lint=${row.lintVersion}|" +
                            "repository=matrix/${row.id}/repository"
                    },
                ) { "offline TestKit manifest is missing ${row.id}" }
                val metadataPath = "matrix/${row.id}/verification-metadata.xml"
                val metadata = zip.getInputStream(zip.getEntry(metadataPath)).bufferedReader().readText()
                require("<verify-metadata>true</verify-metadata>" in metadata) {
                    "offline dependency verification metadata is disabled for ${row.id}"
                }
                require(
                    "group=\"com.android.tools.build\" name=\"gradle\" version=\"${row.agpVersion}\"" in metadata,
                ) { "offline dependency verification metadata is missing AGP ${row.agpVersion}" }
                require(
                    "group=\"com.holin.android.hardening\" name=\"hardening-gradle-plugin\" " +
                        "version=\"${project.version}\"" in metadata,
                ) { "offline dependency verification metadata is missing the exact portable plugin" }
            }
            val forbidden = listOf(
                ".jks", ".keystore", ".p12", ".hardening/", "mapping.txt", "baseline.json",
                ".git/", ".gradle-home/", "/build/outputs/",
            )
            require(names.none { name -> forbidden.any(name.lowercase(Locale.ROOT)::contains) }) {
                "offline TestKit ZIP contains a sensitive path"
            }
            val templateText = required.filter { name -> name.startsWith("fixture-templates/") }
                .joinToString("\n") { name ->
                    zip.getInputStream(zip.getEntry(name)).bufferedReader().readText()
                }
            listOf("/Users/", ".jks", "fixture-password", "BEGIN PRIVATE KEY").forEach { secret ->
                require(secret !in templateText) { "offline fixture templates contain sensitive text" }
            }
            val checksums = zip.getInputStream(zip.getEntry("SHA256SUMS"))
                .bufferedReader()
                .readLines()
                .filter(String::isNotBlank)
                .associate { line -> line.substringAfter("  ") to line.substringBefore("  ") }
            ArchiveChecksumCoverage.requireExhaustive(names, checksums.keys)
            entries.filterNot { entry -> entry.name == "SHA256SUMS" }.forEach { entry ->
                require(checksums.getValue(entry.name) == zip.getInputStream(entry).use(::sha256)) {
                    "offline TestKit checksum mismatch for ${entry.name}"
                }
            }
            val embeddedPortable = zip.getInputStream(zip.getEntry("portable/${portableArchive.get().asFile.name}"))
                .use(::sha256)
            require(embeddedPortable == sha256(portableArchive.get().asFile.toPath())) {
                "offline TestKit does not embed the exact portable ZIP"
            }
        }
        RecursiveArchiveSensitivityScanner.verifyOfflineDistribution(archive.toPath())
    }
}
