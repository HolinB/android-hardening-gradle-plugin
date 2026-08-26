package com.holin.android.hardening.code

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class CodeNamingManifestTest {
    @Test
    fun `manifest accepts an arbitrary included variant and ownership scope`() {
        val manifest = CodeNamingManifest(
            1,
            "trialRelease",
            1,
            linkedSetOf(":shell", ":feature:checkout"),
            "a".repeat(64),
            "b".repeat(64),
            emptyList(),
            emptyList(),
        )

        assertEquals(linkedSetOf(":feature:checkout", ":shell"), manifest.ownedModules)
    }

    @Test
    fun `manifest codec round trips every descriptor and exclusion reason deterministically`() {
        val expected = mutableListOf(
            assignment(CodeSymbolKind.FIELD, "field", "[[I", "calmHarbor"),
            assignment(CodeSymbolKind.METHOD, "call", "(ZBCSIJF[D[[Ljava/lang/String;)Ljava/lang/Object;", "gentleMeadow"),
            assignment(CodeSymbolKind.CLASS, "Owner", "Lcom/example/Owner;", "QuietMeadow"),
        )
        val exclusions = CodeExclusionReason.values().mapIndexed { index, reason ->
            CodeExclusion(
                CodeSymbolKey(CodeSymbolKind.METHOD, "com/example/Excluded$index", "call", "([I)V"),
                reason,
                "evidence for $reason",
            )
        }.toMutableList()
        val manifest = manifest(expected, exclusions)
        expected.clear()
        exclusions.clear()
        val codec = CodeNamingManifestCodec()

        val encoded = codec.encode(manifest)
        val decoded = codec.decode(encoded)

        assertEquals(manifest, decoded)
        assertEquals(encoded, codec.encode(decoded))
        assertTrue(encoded.endsWith("\n"))
        assertFailsWith<UnsupportedOperationException> { (manifest.ownedModules as MutableSet).clear() }
        assertFailsWith<UnsupportedOperationException> { (manifest.expectedSymbols as MutableList).clear() }
        assertFailsWith<UnsupportedOperationException> { (manifest.exclusions as MutableList).clear() }
    }

    @Test
    fun `manifest codec rejects unknown missing and oversized content`() {
        val codec = CodeNamingManifestCodec()
        val valid = codec.encode(manifest(listOf(assignment(CodeSymbolKind.CLASS, "Owner", "Lcom/example/Owner;", "QuietMeadow")), emptyList()))

        assertFailsWith<IllegalArgumentException> {
            codec.decode(valid.replace("\"variant\":", "\"unknown\":0,\"variant\":"))
        }
        assertFailsWith<IllegalArgumentException> {
            codec.decode(valid.replace(Regex(",\"registrySha256\":\"[0-9a-f]{64}\""), ""))
        }
        assertFailsWith<IllegalArgumentException> {
            codec.decode("x".repeat(16 * 1024 * 1024 + 1))
        }
    }

    @Test
    fun `manifest enforces schema variant hashes and nonempty owned modules`() {
        assertFailsWith<IllegalArgumentException> { manifest(emptyList(), emptyList(), schemaVersion = 2) }
        assertFailsWith<IllegalArgumentException> { manifest(emptyList(), emptyList(), variant = "") }
        assertFailsWith<IllegalArgumentException> { manifest(emptyList(), emptyList(), mappingSha256 = "bad") }
        assertFailsWith<IllegalArgumentException> { manifest(emptyList(), emptyList(), ownedModules = emptySet()) }
    }

    @Test
    fun `manifest rejects injected member names and trailing descriptor payloads`() {
        val owner = "com/example/Owner"
        fun malicious(kind: CodeSymbolKind, name: String, descriptor: String) = AssignedCodeName(
            CodeSymbolKey(kind, owner, name, descriptor),
            "calmHarbor",
            "renamed/QuietMeadow",
        )

        assertFailsWith<IllegalArgumentException> {
            manifest(listOf(malicious(CodeSymbolKind.FIELD, "safe\nfield", "I")), emptyList())
        }
        assertFailsWith<IllegalArgumentException> {
            manifest(listOf(malicious(CodeSymbolKind.METHOD, "run bad", "()V")), emptyList())
        }
        assertFailsWith<IllegalArgumentException> {
            manifest(listOf(malicious(CodeSymbolKind.FIELD, "value", "Ipayload")), emptyList())
        }
        assertFailsWith<IllegalArgumentException> {
            manifest(listOf(malicious(CodeSymbolKind.METHOD, "run", "()Vpayload")), emptyList())
        }
    }

    @Test
    fun `schema one decode rejects semantically corrupt naming provenance`() {
        val otherOwner = "com/example/Other"
        val preservedOwner = "com/example/Preserved"
        val codec = CodeNamingManifestCodec()
        val valid = codec.encode(
            manifest(
                expected = listOf(
                    assignment(CodeSymbolKind.CLASS, "Owner", "Lcom/example/Owner;", "QuietMeadow"),
                    assignment(CodeSymbolKind.FIELD, "field", "I", "calmHarbor"),
                    assignment(CodeSymbolKind.METHOD, "call", "()V", "gentleMeadow"),
                    AssignedCodeName(
                        CodeSymbolKey(CodeSymbolKind.CLASS, otherOwner, "Other", "Lcom/example/Other;"),
                        "GentleHarbor",
                        "renamed/GentleHarbor",
                    ),
                ),
                exclusions = listOf(
                    CodeExclusion(
                        CodeSymbolKey(CodeSymbolKind.CLASS, preservedOwner, "Preserved", "L$preservedOwner;"),
                        CodeExclusionReason.UNPROVEN_SOURCE,
                        "class is preserved",
                    ),
                ),
            ),
        )
        val corruptions = listOf(
            valid.replace("\"ownedModules\":[", "\"ownedModules\":[\":app\","),
            valid.replace("\"name\":\"call\"", "\"name\":\"<init>\""),
            valid.replace(
                "\"name\":\"field\",\"descriptor\":\"I\",\"alias\":\"calmHarbor\",\"outputOwner\":\"renamed/QuietMeadow\"",
                "\"name\":\"field\",\"descriptor\":\"I\",\"alias\":\"calmHarbor\",\"outputOwner\":\"renamed/OtherOwner\"",
            ),
            valid.replace("\"alias\":\"calmHarbor\"", "\"alias\":\"gentleMeadow\""),
            valid.replace(
                "\"owner\":\"com/example/Owner\",\"name\":\"field\",\"descriptor\":\"I\",\"alias\":\"calmHarbor\",\"outputOwner\":\"renamed/QuietMeadow\"",
                "\"owner\":\"third/party/Api\",\"name\":\"field\",\"descriptor\":\"I\",\"alias\":\"calmHarbor\",\"outputOwner\":\"third/party/Api\"",
            ),
            valid.replace(
                "\"alias\":\"GentleHarbor\",\"outputOwner\":\"renamed/GentleHarbor\"",
                "\"alias\":\"QUIETMEADOW\",\"outputOwner\":\"renamed/QUIETMEADOW\"",
            ),
            valid.replace(
                "\"alias\":\"GentleHarbor\",\"outputOwner\":\"renamed/GentleHarbor\"",
                "\"alias\":\"PRESERVED\",\"outputOwner\":\"COM/EXAMPLE/PRESERVED\"",
            ),
        )

        corruptions.forEach { corrupted ->
            assertFailsWith<IllegalArgumentException> { codec.decode(corrupted) }
        }
    }

    @Test
    fun `schema one permits member closure through a preserved class exclusion`() {
        val owner = "com/example/Preserved"
        val expected = AssignedCodeName(
            CodeSymbolKey(CodeSymbolKind.METHOD, owner, "call", "()V"),
            "gentleMeadow",
            owner,
        )
        val preservedClass = CodeExclusion(
            CodeSymbolKey(CodeSymbolKind.CLASS, owner, "Preserved", "L$owner;"),
            CodeExclusionReason.UNPROVEN_SOURCE,
            "class is preserved",
        )
        val manifest = manifest(listOf(expected), listOf(preservedClass))

        assertEquals(manifest, CodeNamingManifestCodec().decode(CodeNamingManifestCodec().encode(manifest)))
    }

    @Test
    fun `manifest codec accepts legal Kotlin JVM owners and descriptors`() {
        val owner =
            "com/example/core/net/ServiceCreator\$httpClient_delegate\$lambda\$0\$0\$\$inlined\$-addInterceptor\$1"
        val expected = listOf(
            AssignedCodeName(
                CodeSymbolKey(CodeSymbolKind.CLASS, owner, owner.substringAfterLast('/'), "L$owner;"),
                "QuietMeadow",
                "renamed/QuietMeadow",
            ),
            AssignedCodeName(
                CodeSymbolKey(CodeSymbolKind.FIELD, owner, "interceptor", "L$owner;"),
                "calmHarbor",
                "renamed/QuietMeadow",
            ),
            AssignedCodeName(
                CodeSymbolKey(CodeSymbolKind.METHOD, owner, "install", "(L$owner;)L$owner;"),
                "gentleMeadow",
                "renamed/QuietMeadow",
            ),
        )
        val codec = CodeNamingManifestCodec()

        val manifest = manifest(expected, emptyList())

        assertEquals(manifest, codec.decode(codec.encode(manifest)))
    }

    @Test
    fun `manifest rejects illegal JVM internal names and malformed output owners`() {
        val validOwner = "com/example/Owner"
        listOf("com//example/Owner", "com/example/Invalid.Name", "com/example/Invalid;Name", "com/example/Invalid[Name")
            .forEach { owner ->
                assertFailsWith<IllegalArgumentException> {
                    manifest(
                        listOf(AssignedCodeName(
                            CodeSymbolKey(CodeSymbolKind.FIELD, owner, "field", "I"),
                            "calmHarbor",
                            "renamed/QuietMeadow",
                        )),
                        emptyList(),
                    )
                }
            }
        listOf("Lcom//example/Owner;", "Lcom/example/Invalid.Name;", "Lcom/example/Invalid;Name;", "Lcom/example/Invalid[Name;")
            .forEach { descriptor ->
                assertFailsWith<IllegalArgumentException> {
                    manifest(listOf(assignment(CodeSymbolKind.FIELD, "field", descriptor, "calmHarbor")), emptyList())
                }
            }
        assertFailsWith<IllegalArgumentException> {
            manifest(
                listOf(AssignedCodeName(
                    CodeSymbolKey(CodeSymbolKind.CLASS, validOwner, "Owner", "L$validOwner;"),
                    "QuietMeadow",
                    "renamed/-addInterceptor",
                )),
                emptyList(),
            )
        }
    }

    private fun assignment(kind: CodeSymbolKind, name: String, descriptor: String, alias: String): AssignedCodeName {
        val owner = "com/example/Owner"
        val outputOwner = if (kind == CodeSymbolKind.CLASS) "renamed/$alias" else "renamed/QuietMeadow"
        return AssignedCodeName(CodeSymbolKey(kind, owner, name, descriptor), alias, outputOwner)
    }

    private fun manifest(
        expected: Collection<AssignedCodeName>,
        exclusions: Collection<CodeExclusion>,
        schemaVersion: Int = 1,
        variant: String = "demoDebug",
        mappingSha256: String = "a".repeat(64),
        ownedModules: Set<String> = setOf(":app", ":core", ":compress", ":selector", ":ucrop"),
    ) = CodeNamingManifest(
        schemaVersion = schemaVersion,
        variant = variant,
        generation = 3,
        ownedModules = ownedModules,
        mappingSha256 = mappingSha256,
        registrySha256 = "b".repeat(64),
        expectedSymbols = expected,
        exclusions = exclusions,
    )
}
