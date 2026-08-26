package com.holin.android.hardening

import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.value.ArrayEncodedValue
import com.android.tools.smali.dexlib2.iface.value.BooleanEncodedValue
import com.android.tools.smali.dexlib2.iface.value.StringEncodedValue
import com.holin.android.hardening.verification.ParsedR8Mapping
import com.holin.android.hardening.verification.R8MappingParser
import com.holin.android.hardening.verification.SymbolKind as MappingSymbolKind
import groovy.json.JsonSlurper
import java.nio.file.Path
import java.util.zip.ZipFile
import kotlin.io.path.createDirectories
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.gradle.testkit.runner.GradleRunner
import org.junit.jupiter.api.io.TempDir

class AgpStableCodeNamingContinuityFunctionalTest {
    @TempDir
    lateinit var projectDirectory: Path

    @Test
    fun `two debug builds preserve Bean fields and stable class method aliases`() {
        writeFiveModuleDebugFixture()
        seedLegacyFieldAssignment()
        val seeded = activeRegistry()
        val legacyField = seeded.assignment(RETIRED_FIELD_KEY)
        val seededIdentity = activeIdentity()

        val firstReport = runHardenedDebug()
        val first = activeRegistry()
        val firstIdentity = activeIdentity()
        assertFixtureContracts(first)
        assertPassingMappingReport(firstReport, 1)
        assertRetiredTombstone(legacyField, first, first.generation)
        assertNoFieldAssignments(first)
        assertEquals(seeded.seedSha256, first.seedSha256)
        assertEquals(seededIdentity, firstIdentity)

        addOwnedSymbol("com.example.core.Added", "calculate", "()I")
        val secondReport = runHardenedDebug()
        val second = activeRegistry()
        assertRegistryTransition(
            first,
            second,
            setOf(SymbolKind.PACKAGE, SymbolKind.CLASS, SymbolKind.MEMBER),
            expectedAdded = setOf(ADDED_CLASS_KEY, CALCULATE_METHOD_KEY),
        )
        assertPassingMappingReport(secondReport, 0)
        assertRetiredTombstone(legacyField, second, first.generation)
        assertNoFieldAssignments(second)
        assertEquals(first.seedSha256, second.seedSha256)
        assertEquals(firstIdentity, activeIdentity())
        assertTrue(second.assignments.groupBy { assignment ->
            Triple(assignment.namespace, assignment.key.kind, assignment.alias.lowercase())
        }.values.none { assignments -> assignments.size > 1 })
        assertFalse(debugRoot().resolve("quarantine").toFile().exists())
        assertFinalDexGsonAnnotations()
    }

    @Test
    fun `registry decoder rejects duplicate keys`() {
        assertFailsWith<IllegalArgumentException> {
            decodeRegistry(duplicateRegistryJson())
        }
    }

    @Test
    fun `registry transition rejects duplicate assignment keys`() {
        val first = registry(assignment("field:Owner#firstI"), assignment("field:Owner#secondI"))
        val second = registry(
            assignment("field:Owner#firstI"),
            assignment("field:Owner#firstI"),
            assignment("field:Owner#secondI"),
        )

        assertFailsWith<AssertionError> {
            assertRegistryTransition(first, second, setOf(SymbolKind.MEMBER))
        }
    }

    @Test
    fun `registry transition rejects an unexpected disappeared key`() {
        val first = registry(assignment("field:Owner#firstI"), assignment("field:Owner#secondI"))
        val second = registry(assignment("field:Owner#firstI"))

        assertFailsWith<AssertionError> {
            assertRegistryTransition(first, second, setOf(SymbolKind.MEMBER))
        }
    }

    @Test
    fun `registry transition requires a shared key for every requested kind`() {
        val first = registry(assignment("field:Owner#valueI"))
        val second = registry(assignment("field:Owner#valueI"))

        assertFailsWith<AssertionError> {
            assertRegistryTransition(first, second, setOf(SymbolKind.CLASS, SymbolKind.MEMBER))
        }
    }

    @Test
    fun `exact assignment lookup rejects malformed actual kind and descriptor`() {
        val malformed = registry(
            RegistryAssignment(
                key = ADDED_CLASS_KEY.copy(kind = SymbolKind.MEMBER, descriptor = "I"),
                namespace = "code-members-v2",
                alias = "quietRiver",
                keyHash = "a".repeat(64),
            ),
        )

        assertFailsWith<NoSuchElementException> {
            malformed.assignment(ADDED_CLASS_KEY)
        }
    }

    @Test
    fun `retired tombstone helper rejects unrelated tombstone and active alias collision`() {
        val retired = assignment("field:Owner#retiredI", alias = "quietRiver", keyHash = "a".repeat(64))
        val unrelated = RegistryTombstone(
            namespace = retired.namespace,
            kind = retired.key.kind,
            alias = retired.alias,
            keyHash = "b".repeat(64),
            retiredGeneration = 2,
        )
        val snapshot = registry(
            assignment("field:Owner#activeI", alias = retired.alias, keyHash = "c".repeat(64)),
            tombstones = listOf(unrelated),
            generation = 2,
        )

        assertFailsWith<AssertionError> {
            assertRetiredTombstone(retired, snapshot)
        }
    }

    @Test
    fun `retired tombstone helper rejects active alias reuse`() {
        val retired = assignment("field:Owner#retiredI", alias = "quietRiver", keyHash = "a".repeat(64))
        val exact = RegistryTombstone(
            namespace = retired.namespace,
            kind = retired.key.kind,
            alias = retired.alias,
            keyHash = retired.keyHash,
            retiredGeneration = 2,
        )
        val snapshot = registry(
            assignment("field:Owner#activeI", alias = retired.alias, keyHash = "c".repeat(64)),
            tombstones = listOf(exact),
            generation = 2,
        )

        assertFailsWith<AssertionError> {
            assertRetiredTombstone(retired, snapshot)
        }
    }

    @Test
    fun `mapping report helper rejects misleading nested pass fields`() {
        val misleading =
            """{"status":"FAIL","currentMappingSha256":"${"a".repeat(64)}","preparedMappingSha256":"${"b".repeat(64)}","continuity":{"status":"PASS","mismatches":[]},"retraceVerified":false,"violations":["failed"]}"""

        assertFailsWith<IllegalArgumentException> {
            assertPassingMappingReport(misleading)
        }
    }

    private fun writeFiveModuleDebugFixture() {
        AgpPublicWiringFunctionalTest().also { fixture ->
            fixture.projectDirectory = projectDirectory
            fixture.writeAndroidFixture(
                maximumOverallExclusive = 100.0,
                includeDebug = true,
                includeOwnedModules = true,
                includeOwnedResources = false,
            )
        }
        writeBaseSource()
        val manifest = projectDirectory.resolve("app/src/main/AndroidManifest.xml")
        manifest.writeText(
            manifest.readText().replace(
                "<application>",
                "<application android:name=\"com.example.core.Base\">",
            ),
        )
        val compress = projectDirectory.resolve("compress")
        compress.resolve("src/main/java/com/example/compress/Compress.java").writeText(
            """
            package com.example.compress;

            import com.example.core.Base;

            public final class Compress extends Base {
                @Override public int ownedOverride() { return 2; }
            }
            """.trimIndent(),
        )
        compress.resolve("build.gradle").toFile().appendText(
            """

            dependencies { api project(':core') }
            """.trimIndent(),
        )
        projectDirectory.resolve("core/build.gradle").toFile().appendText(
            """

            dependencies { implementation 'com.google.code.gson:gson:2.13.2' }
            """.trimIndent(),
        )
        projectDirectory.resolve("app/build.gradle").toFile().appendText(
            """

            dependencies { implementation 'com.google.code.gson:gson:2.13.2' }

            tasks.register('seedLegacyFieldAssignment') {
                dependsOn 'prepareHardeningDemoDebug'
                doLast {
                    def preparedPath = tasks.named('prepareHardeningDemoDebug').get()
                        .preparedDirectory.get().asFile.toPath()
                    def prepared = com.holin.android.hardening.state.PreparedStateCodec.INSTANCE.read(
                        preparedPath.resolve('prepared-state.properties'),
                    )
                    def seed = java.nio.file.Files.readAllBytes(preparedPath.resolve('seed.bin'))
                    def codec = new com.holin.android.hardening.naming.RegistryCodec()
                    def snapshot = codec.decode(java.nio.file.Files.readString(preparedPath.resolve('registry.json')))
                    def registry = com.holin.android.hardening.naming.PseudowordRegistry.@Companion.restore(seed, snapshot)
                    def key = new com.holin.android.hardening.naming.RegistryKey(
                        'field:com/example/core/Base#retiredI',
                        com.holin.android.hardening.naming.SymbolKind.MEMBER,
                        'I',
                    )
                    def request = new com.holin.android.hardening.naming.AliasRequest(
                        key,
                        'code-members-v2',
                        [] as Set,
                    )
                    registry.reconcileScoped(
                        [request],
                        prepared.identity.generation,
                        [com.holin.android.hardening.naming.SymbolKind.MEMBER] as Set,
                        [:],
                    )
                    java.nio.file.Files.writeString(
                        preparedPath.resolve('registry.json'),
                        codec.encode(registry.snapshot(prepared.identity.generation)),
                    )
                    new com.holin.android.hardening.state.StateStore().archive(
                        new com.holin.android.hardening.state.ArchiveRequest(
                            prepared,
                            1,
                            'e' * 64,
                        ),
                    )
                }
            }
            """.trimIndent(),
        )
    }

    private fun addOwnedSymbol(className: String, methodName: String, descriptor: String) {
        assertEquals("com.example.core.Added", className)
        assertEquals("calculate", methodName)
        assertEquals("()I", descriptor)
        projectDirectory.resolve("core/src/main/java/com/example/core/Added.java").writeText(
            "package com.example.core; public final class Added { public int calculate() { return 7; } }\n",
        )
    }

    private fun writeBaseSource() {
        val source = projectDirectory.resolve("core/src/main/java/com/example/core/Base.java")
        source.parent.createDirectories()
        source.writeText(
            """
            package com.example.core;

            import android.os.Bundle;
            import com.google.gson.Gson;
            import com.google.gson.GsonBuilder;
            import com.google.gson.annotations.Expose;
            import com.google.gson.annotations.SerializedName;

            public class Base extends android.app.Application implements Runnable {
                public String beanValue;
                public Object binding;
                public Object value${'$'}delegate;
                public int retired;
                @SerializedName(value = "display_name", alternate = {"displayName"})
                @Expose(deserialize = false)
                public String annotatedValue;

                @Override public void onCreate() {
                    super.onCreate();
                    Gson gson = new GsonBuilder().excludeFieldsWithoutExposeAnnotation().create();
                    annotatedValue = "fixture";
                    android.util.Log.d("fixture", gson.toJson(this));
                }

                public int ownedOverride() { return 1; }
                public int describe(Bundle dependency) { return dependency == null ? 0 : 1; }
                @Override public void run() {}
            }
            """.trimIndent(),
        )
    }

    private fun seedLegacyFieldAssignment() {
        runner(
            "-PandroidHardening=true",
            "prepareHardeningDemoDebug",
            "seedLegacyFieldAssignment",
        ).build()
    }

    private fun runHardenedDebug(): String {
        runner("-PandroidHardening=true", "hardeningAssembleDemoDebug").build()
        return projectDirectory.resolve(
            "app/build/reports/hardening/demoDebug/mapping-verification.json",
        ).readText()
    }

    private fun assertPassingMappingReport(report: String, expectedRetiredLegacyFields: Int = 0) {
        val root = jsonObject(report)
        assertEquals(2L, jsonLong(root, "schemaVersion"))
        assertEquals("PASS", jsonString(root, "status"))
        val continuity = jsonObject(root, "continuity")
        assertTrue(jsonArray(continuity, "mismatches").isEmpty())
        assertTrue(jsonBoolean(root, "retraceVerified"))
        assertTrue(jsonArray(root, "violations").isEmpty())
        assertEquals(
            jsonString(root, "currentMappingSha256"),
            jsonString(root, "preparedMappingSha256"),
        )
        val fields = jsonObject(root, "potentialBeanFields")
        assertTrue(jsonBoolean(fields, "verified"))
        assertTrue(jsonArray(fields, "violations").isEmpty())
        assertTrue(jsonLong(fields, "protectedFieldCount") > 0)
        assertEquals(
            setOf(":app", ":core", ":compress", ":selector", ":ucrop"),
            jsonObject(fields, "moduleFieldCounts").keys,
        )
        assertTrue(jsonLong(root, "renamedOwnedClasses") > 0)
        assertTrue(jsonLong(root, "renamedOwnedMethods") > 0)
        assertEquals(expectedRetiredLegacyFields.toLong(), jsonLong(root, "retiredLegacyFieldAssignmentCount"))
    }

    private fun activeRegistry(): RegistrySnapshot {
        return decodeRegistry(activeSnapshot().resolve("registry.json").readText())
    }

    private fun decodeRegistry(json: String): RegistrySnapshot {
        val registry = jsonObject(json)
        return RegistrySnapshot(
            jsonLong(registry, "generation"),
            jsonString(registry, "seedSha256"),
            jsonArray(registry, "assignments").map { raw ->
                val assignment = requireNotNull(raw as? Map<*, *>)
                RegistryAssignment(
                    key = RegistryKey(
                        originalIdentity = jsonString(assignment, "originalIdentity"),
                        kind = enumValueOf(jsonString(assignment, "kind")),
                        descriptor = jsonString(assignment, "descriptor"),
                    ),
                    namespace = jsonString(assignment, "namespace"),
                    alias = jsonString(assignment, "alias"),
                    keyHash = jsonString(assignment, "keyHash"),
                )
            },
            jsonArray(registry, "tombstones").map { raw ->
                val tombstone = requireNotNull(raw as? Map<*, *>)
                RegistryTombstone(
                    namespace = jsonString(tombstone, "namespace"),
                    kind = enumValueOf(jsonString(tombstone, "kind")),
                    alias = jsonString(tombstone, "alias"),
                    keyHash = jsonString(tombstone, "keyHash"),
                    retiredGeneration = jsonLong(tombstone, "retiredGeneration"),
                )
            },
        ).also { snapshot ->
            require(snapshot.assignments.map(RegistryAssignment::key).distinct().size == snapshot.assignments.size) {
                "registry assignments contain duplicate RegistryKey values"
            }
        }
    }

    private fun assertRetiredTombstone(
        retired: RegistryAssignment,
        snapshot: RegistrySnapshot,
        expectedRetiredGeneration: Long = snapshot.generation,
    ) {
        val matching = snapshot.tombstones.filter { tombstone ->
            tombstone.namespace == retired.namespace &&
                tombstone.kind == retired.key.kind &&
                tombstone.alias == retired.alias &&
                tombstone.keyHash == retired.keyHash &&
                tombstone.retiredGeneration == expectedRetiredGeneration
        }
        assertEquals(1, matching.size, "retired assignment must have one exact tombstone")
        assertTrue(
            snapshot.assignments.none { assignment ->
                assignment.namespace == retired.namespace &&
                    assignment.key.kind == retired.key.kind &&
                    assignment.alias == retired.alias
            },
            "retired alias remains active in its namespace and kind",
        )
    }

    private fun assertFixtureContracts(registry: RegistrySnapshot) {
        assertNoFieldAssignments(registry)
        assertTrue(registry.assignments.any { assignment ->
            assignment.key.descriptor.contains("com/example/core/Base#ownedOverride()I") &&
                assignment.key.descriptor.contains("com/example/compress/Compress#ownedOverride()I")
        })
        assertTrue(registry.assignments.any { assignment ->
            assignment.key.descriptor.contains("com/example/core/Base#describe(Landroid/os/Bundle;)I")
        })
        assertFalse(registry.assignments.any { assignment ->
            assignment.key.originalIdentity.contains("#run()V") || assignment.key.descriptor.contains("#run()V")
        })
        val namingManifest = jsonObject(
            projectDirectory.resolve("app/build/reports/hardening/demoDebug/code-naming.json").readText(),
        )
        assertTrue(jsonArray(namingManifest, "exclusions").any { raw ->
            val exclusion = requireNotNull(raw as? Map<*, *>)
            jsonString(exclusion, "owner") == "com/example/core/Base" &&
                jsonString(exclusion, "name") == "run" &&
                jsonString(exclusion, "descriptor") == "()V" &&
                jsonString(exclusion, "reason") == "EXTERNAL_OVERRIDE"
        })
        val potentialBeanManifest = jsonObject(
            projectDirectory.resolve("app/build/reports/hardening/demoDebug/potential-bean-fields.json").readText(),
        )
        assertTrue(jsonArray(potentialBeanManifest, "fields").any { raw ->
            val field = requireNotNull(raw as? Map<*, *>)
            jsonString(field, "owner") == "com/example/core/Base" &&
                jsonString(field, "name") == "annotatedValue"
        })
    }

    private fun assertNoFieldAssignments(registry: RegistrySnapshot) {
        assertTrue(registry.assignments.none { assignment -> assignment.key.originalIdentity.startsWith("field:") })
    }

    private fun assertFinalDexGsonAnnotations() {
        val mapping = R8MappingParser().parse(activeSnapshot().resolve("mapping.txt"), null)
        val aab = projectDirectory.resolve(
            "app/build/outputs/hardening/demoDebug/demoDebug-hardened.aab",
        )
        val matchingFields = ZipFile(aab.toFile()).use { zip ->
            zip.entries().asSequence()
                .filter { entry -> !entry.isDirectory && BASE_DEX_PATH.matches(entry.name) }
                .flatMap { entry ->
                    val bytes = zip.getInputStream(entry).use { input -> input.readBytes() }
                    DexBackedDexFile.fromInputStream(null, bytes.inputStream()).classes.asSequence()
                }
                .flatMap { clazz -> clazz.fields.asSequence() }
                .filter { field -> field.name == "annotatedValue" }
                .toList()
        }
        val field = matchingFields.single()
        val annotations = field.annotations.associateBy { annotation -> annotation.type }
        val serializedOwner = "com.google.gson.annotations.SerializedName"
        val serialized = annotations.getValue(mappedDescriptor(mapping, serializedOwner))
            .elements.associateBy { element -> element.name }
        val valueName = mappedMethod(mapping, serializedOwner, "value", "()Ljava/lang/String;")
        val alternateName = mappedMethod(mapping, serializedOwner, "alternate", "()[Ljava/lang/String;")
        assertEquals("display_name", (serialized.getValue(valueName).value as StringEncodedValue).value)
        assertEquals(
            listOf("displayName"),
            (serialized.getValue(alternateName).value as ArrayEncodedValue).value.map { value ->
                (value as StringEncodedValue).value
            },
        )
        val exposeOwner = "com.google.gson.annotations.Expose"
        val expose = annotations.getValue(mappedDescriptor(mapping, exposeOwner))
            .elements.associateBy { element -> element.name }
        val deserializeName = mappedMethod(mapping, exposeOwner, "deserialize", "()Z")
        assertFalse((expose.getValue(deserializeName).value as BooleanEncodedValue).value)
    }

    private fun mappedDescriptor(mapping: ParsedR8Mapping, originalOwner: String): String {
        val output = mapping.symbols.entries.single { (key, _) ->
            key.kind == MappingSymbolKind.CLASS && key.originalOwner == originalOwner
        }.value.single()
        return "L${output.replace('.', '/')};"
    }

    private fun mappedMethod(
        mapping: ParsedR8Mapping,
        originalOwner: String,
        originalName: String,
        descriptor: String,
    ): String = mapping.symbols.entries.single { (key, _) ->
        key.kind == MappingSymbolKind.METHOD &&
            key.originalOwner == originalOwner &&
            key.originalName == originalName &&
            key.jvmDescriptor == descriptor
    }.value.single()

    private fun assertRegistryTransition(
        first: RegistrySnapshot,
        second: RegistrySnapshot,
        kinds: Set<SymbolKind>,
        expectedRemoved: Set<RegistryKey> = emptySet(),
        expectedAdded: Set<RegistryKey> = emptySet(),
    ) {
        val firstSelected = first.assignments.filter { it.key.kind in kinds }
        val secondSelected = second.assignments.filter { it.key.kind in kinds }
        val firstByKey = firstSelected.associateBy(RegistryAssignment::key)
        val secondByKey = secondSelected.associateBy(RegistryAssignment::key)
        assertEquals(firstSelected.size, firstByKey.size, "first registry contains duplicate keys")
        assertEquals(secondSelected.size, secondByKey.size, "second registry contains duplicate keys")
        assertEquals(expectedRemoved, firstByKey.keys - secondByKey.keys, "unexpected removed registry keys")
        assertEquals(expectedAdded, secondByKey.keys - firstByKey.keys, "unexpected added registry keys")
        val shared = firstByKey.keys intersect secondByKey.keys
        assertEquals(kinds, shared.mapTo(linkedSetOf(), RegistryKey::kind), "requested registry kind has no shared key")
        shared.forEach { key ->
            assertEquals(firstByKey.getValue(key).alias, secondByKey.getValue(key).alias, key.toString())
            assertEquals(firstByKey.getValue(key).namespace, secondByKey.getValue(key).namespace, key.toString())
        }
    }

    private fun RegistrySnapshot.assignment(expected: RegistryKey): RegistryAssignment =
        assignments.single { assignment -> assignment.key == expected }

    private fun activeSnapshot(): Path {
        val current = debugRoot().resolve("current")
        val active = jsonObject(current.resolve("active.json").readText())
        val snapshotId = jsonString(active, "snapshotId")
        return current.resolve("snapshots/$snapshotId")
    }

    private fun activeIdentity(): ActiveIdentity {
        val manifest = jsonObject(activeSnapshot().resolve("manifest.json").readText())
        val identity = jsonObject(manifest, "identity")
        return ActiveIdentity(
            jsonString(identity, "lineageId"),
            jsonString(identity, "seedHash"),
        )
    }

    private fun jsonObject(json: String): Map<*, *> =
        requireNotNull(JsonSlurper().parseText(json) as? Map<*, *>) { "expected a JSON object" }

    private fun jsonObject(json: Map<*, *>, field: String): Map<*, *> =
        requireNotNull(json[field] as? Map<*, *>) { "missing JSON object field $field" }

    private fun jsonArray(json: Map<*, *>, field: String): List<*> =
        requireNotNull(json[field] as? List<*>) { "missing JSON array field $field" }

    private fun jsonString(json: Map<*, *>, field: String): String =
        requireNotNull(json[field] as? String) { "missing JSON string field $field" }

    private fun jsonLong(json: Map<*, *>, field: String): Long =
        requireNotNull(json[field] as? Number) { "missing JSON numeric field $field" }.toLong()

    private fun jsonBoolean(json: Map<*, *>, field: String): Boolean =
        requireNotNull(json[field] as? Boolean) { "missing JSON boolean field $field" }

    private fun registry(
        vararg assignments: RegistryAssignment,
        tombstones: List<RegistryTombstone> = emptyList(),
        generation: Long = 1,
    ): RegistrySnapshot = RegistrySnapshot(
        generation,
        "a".repeat(64),
        assignments.toList(),
        tombstones,
    )

    private fun assignment(
        originalIdentity: String,
        alias: String = "quietRiver",
        keyHash: String = "a".repeat(64),
    ): RegistryAssignment = RegistryAssignment(
        key = RegistryKey(originalIdentity, SymbolKind.MEMBER, "I"),
        namespace = "code-members-v2",
        alias = alias,
        keyHash = keyHash,
    )

    private fun duplicateRegistryJson(): String {
        val assignment =
            """{"originalIdentity":"field:Owner#valueI","kind":"MEMBER","descriptor":"I","namespace":"code-members-v2","alias":"quietRiver","keyHash":"${"a".repeat(64)}"}"""
        return """{"generation":1,"assignments":[$assignment,$assignment],"tombstones":[]}"""
    }

    private fun debugRoot(): Path = projectDirectory.resolve("fixture-state/demo/demoDebug")

    private fun runner(vararg arguments: String): GradleRunner = GradleRunner.create()
        .withProjectDir(projectDirectory.toFile())
        .withTestKitDir(sharedGradleUserHome().toFile())
        .withArguments("--offline", "--stacktrace", *arguments)

    private fun sharedGradleUserHome(): Path = Path.of(
        System.getenv("GRADLE_USER_HOME")
            ?: "${System.getProperty("user.home")}/.gradle",
    )

    private companion object {
        val BASE_DEX_PATH = Regex("base/dex/classes(?:[0-9]+)?\\.dex")
    }
}

private enum class SymbolKind { CLASS, MEMBER, PACKAGE, RESOURCE }

private data class RegistryKey(
    val originalIdentity: String,
    val kind: SymbolKind,
    val descriptor: String,
)

private data class RegistryAssignment(
    val key: RegistryKey,
    val namespace: String,
    val alias: String,
    val keyHash: String,
)

private data class RegistryTombstone(
    val namespace: String,
    val kind: SymbolKind,
    val alias: String,
    val keyHash: String,
    val retiredGeneration: Long,
)

private data class RegistrySnapshot(
    val generation: Long,
    val seedSha256: String,
    val assignments: List<RegistryAssignment>,
    val tombstones: List<RegistryTombstone>,
)

private data class ActiveIdentity(
    val lineageId: String,
    val seedHash: String,
)

private val ADDED_CLASS_KEY = RegistryKey(
    originalIdentity = "com/example/core/Added#AddedLcom/example/core/Added;",
    kind = SymbolKind.CLASS,
    descriptor = "Lcom/example/core/Added;",
)

private val RETIRED_FIELD_KEY = RegistryKey(
    originalIdentity = "field:com/example/core/Base#retiredI",
    kind = SymbolKind.MEMBER,
    descriptor = "I",
)

private val CALCULATE_METHOD_KEY = RegistryKey(
    originalIdentity = "override:com/example/core/Added#calculate()I",
    kind = SymbolKind.MEMBER,
    descriptor = "method-group-v2\ncom/example/core/Added#calculate()I",
)
