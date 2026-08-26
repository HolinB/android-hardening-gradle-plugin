package com.holin.android.hardening.verification

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull

class R8MappingParserTest {
    @Test
    fun `parses app classes fields methods JVM descriptors and retrace lines`() {
        val mapping = """
            # compiler: R8
            # compiler_version: 8.13.19
            # {"id":"com.android.tools.r8.mapping","version":"2.2"}
            com.example.Foo -> a.b:
            # {"id":"sourceFile","fileName":"Foo.kt"}
                int count -> c
                java.lang.String[] labels -> d
                7:7:void work(java.lang.String,int[]):42:42 -> e
                8:8:java.lang.String com.example.Other.inlined(long):99:99 -> f
            com.example.Foo${'$'}Nested -> a.c:
                9:9:boolean ready():51:51 -> g
            com.example.Unowned -> z:
                1:1:void ignored():10:10 -> a
        """.trimIndent()

        val parsed = R8MappingParser().parse(
            mapping,
            ownedOriginalDescriptors = setOf("Lcom/example/Foo;"),
        )

        assertEquals("R8", parsed.compiler)
        assertEquals("8.13.19", parsed.compilerVersion)
        assertEquals(
            setOf(
                MappingSymbolKey(SymbolKind.CLASS, "com.example.Foo", "com.example.Foo", "Lcom/example/Foo;"),
                MappingSymbolKey(SymbolKind.CLASS, "com.example.Foo${'$'}Nested", "com.example.Foo${'$'}Nested", "Lcom/example/Foo${'$'}Nested;"),
                MappingSymbolKey(SymbolKind.FIELD, "com.example.Foo", "count", "I"),
                MappingSymbolKey(SymbolKind.FIELD, "com.example.Foo", "labels", "[Ljava/lang/String;"),
                MappingSymbolKey(SymbolKind.METHOD, "com.example.Foo", "work", "(Ljava/lang/String;[I)V"),
                MappingSymbolKey(SymbolKind.METHOD, "com.example.Foo${'$'}Nested", "ready", "()Z"),
            ),
            parsed.symbols.keys,
        )
        assertEquals(setOf("a.b"), parsed.symbols.getValue(parsed.symbols.keys.first { it.kind == SymbolKind.CLASS }))
        val candidate = assertNotNull(parsed.retraceCandidates.single { it.originalMethod == "work" })
        assertEquals("at a.b.e(HardeningSource:7)", candidate.obfuscatedFrame)
        assertEquals(42, candidate.originalLine)
    }

    @Test
    fun `parses mapping without compiler metadata for prepared app only input`() {
        val parsed = R8MappingParser().parse(
            "com.example.Foo -> a:\n    1:1:void run():12:12 -> b\n",
            ownedOriginalDescriptors = null,
        )

        assertEquals(null, parsed.compiler)
        assertEquals(null, parsed.compilerVersion)
        assertEquals(2, parsed.symbols.size)
    }

    @Test
    fun `method symbols use residual names and ignore inlined and synthesized copies`() {
        val parsed = R8MappingParser().parse(
            """
            com.example.Foo -> a:
                1:3:void run():0:0 -> a
                  # {"id":"com.android.tools.r8.synthesized"}
                4:4:void run():10:10 -> b
                5:5:void run():11:11 -> c
                5:5:void host():20:20 -> c
            """.trimIndent(),
            ownedOriginalDescriptors = null,
        )

        assertEquals(
            setOf("b"),
            parsed.symbols.getValue(
                MappingSymbolKey(SymbolKind.METHOD, "com.example.Foo", "run", "()V"),
            ),
        )
        assertEquals(
            setOf("c"),
            parsed.symbols.getValue(
                MappingSymbolKey(SymbolKind.METHOD, "com.example.Foo", "host", "()V"),
            ),
        )
    }

    @Test
    fun `parses legal Kotlin JVM names in mapping classes and member types`() {
        val owner =
            "com.example.core.net.ServiceCreator\$httpClient_delegate\$lambda\$0\$0\$\$inlined\$-addInterceptor\$1"
        val descriptor = "L${owner.replace('.', '/')};"

        val parsed = R8MappingParser().parse(
            """
            $owner -> a:
                $owner interceptor -> b
                $owner install($owner) -> c
            """.trimIndent(),
            ownedOriginalDescriptors = null,
        )

        assertEquals(
            setOf(
                MappingSymbolKey(SymbolKind.CLASS, owner, owner, descriptor),
                MappingSymbolKey(SymbolKind.FIELD, owner, "interceptor", descriptor),
                MappingSymbolKey(SymbolKind.METHOD, owner, "install", "($descriptor)$descriptor"),
            ),
            parsed.symbols.keys,
        )
    }

    @Test
    fun `rejects illegal dotted JVM names in mapping classes and member types`() {
        listOf("com..example.Invalid", "com.example.Invalid/Name", "com.example.Invalid;Name", "com.example.Invalid[Name")
            .forEach { className ->
                assertFailsWith<IllegalArgumentException> {
                    R8MappingParser().parse("$className -> a:", ownedOriginalDescriptors = null)
                }
            }
        listOf("com..example.Invalid", "com.example.Invalid/Name", "com.example.Invalid;Name", "com.example.Invalid[Name")
            .forEach { type ->
                assertFailsWith<IllegalArgumentException> {
                    R8MappingParser().parse(
                        "com.example.Owner -> a:\n    $type value -> b",
                        ownedOriginalDescriptors = null,
                    )
                }
            }
    }
}
