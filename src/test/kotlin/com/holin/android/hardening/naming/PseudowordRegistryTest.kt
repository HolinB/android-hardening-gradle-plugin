package com.holin.android.hardening.naming

import com.holin.android.hardening.state.Sha256
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.test.assertFalse

class PseudowordRegistryTest {
    private val seed = Sha256.digest("stable-lineage-seed".toByteArray())

    @Test
    fun `aliases have a shape specific to symbol kind`() {
        val registry = PseudowordRegistry(seed)

        val classRequest = AliasRequest(RegistryKey("pkg.Type", SymbolKind.CLASS, "Lpkg/Type;"), "pkg")
        val memberRequest = AliasRequest(RegistryKey("pkg.Type#value", SymbolKind.MEMBER, "()I"), "pkg.Type")
        val packageRequest = AliasRequest(RegistryKey("pkg", SymbolKind.PACKAGE, "package"), "root")
        val resourceRequest = AliasRequest(RegistryKey("layout/main", SymbolKind.RESOURCE, "layout"), "app")
        val aliases = registry.reconcile(listOf(classRequest, memberRequest, packageRequest, resourceRequest), generation = 1)

        assertTrue(aliases.getValue(classRequest.key).matches(Regex("[A-Z][A-Za-z0-9]*")))
        assertTrue(aliases.getValue(memberRequest.key).matches(Regex("[a-z][A-Za-z0-9]*")))
        assertTrue(aliases.getValue(packageRequest.key).matches(Regex("[a-z][a-z0-9]*")))
        assertTrue(aliases.getValue(resourceRequest.key).matches(Regex("[a-z][a-z0-9]*_[a-z0-9_]+")))
    }

    @Test
    fun `registry exposes only deterministic batch reconciliation`() {
        assertFalse(PseudowordRegistry::class.java.methods.any { it.name == "allocate" })
    }

    @Test
    fun `registry requires a 32 byte lineage seed`() {
        assertFailsWith<IllegalArgumentException> { PseudowordRegistry(ByteArray(31)) }
        val registry = PseudowordRegistry(seed)
        val snapshot = registry.snapshot(generation = 1)
        assertFailsWith<IllegalArgumentException> { PseudowordRegistry.restore(ByteArray(31), snapshot) }
    }

    @Test
    fun `allocation is deterministic and descriptor is part of identity`() {
        val first = PseudowordRegistry(seed)
        val second = PseudowordRegistry(seed)
        val key = AliasRequest(RegistryKey("pkg.Type#call", SymbolKind.MEMBER, "(I)V"), "pkg.Type")
        val descriptorVariant = key.copy(key = key.key.copy(descriptor = "(J)V"))
        val firstAliases = first.reconcile(listOf(key, descriptorVariant), generation = 1)
        val secondAliases = second.reconcile(listOf(key, descriptorVariant).reversed(), generation = 1)

        assertEquals(firstAliases.getValue(key.key), secondAliases.getValue(key.key))
        assertNotEquals(firstAliases.getValue(key.key), firstAliases.getValue(descriptorVariant.key))
    }

    @Test
    fun `collision probing is scoped by namespace and kind`() {
        val candidates: (AliasRequest, Int) -> String = { request, probe ->
            when (request.key.kind) {
                SymbolKind.CLASS -> if (probe == 0) "CalmRiver" else "BrightStone"
                else -> error("unexpected kind")
            }
        }
        val registry = PseudowordRegistry(seed, candidateFactory = candidates)
        val first = AliasRequest(RegistryKey("pkg.First", SymbolKind.CLASS, "Lpkg/First;"), "pkg")
        val second = AliasRequest(RegistryKey("pkg.Second", SymbolKind.CLASS, "Lpkg/Second;"), "pkg")
        val otherNamespace = AliasRequest(RegistryKey("other.Third", SymbolKind.CLASS, "Lother/Third;"), "other")

        val aliases = registry.reconcile(listOf(first, second, otherNamespace), generation = 1)
        assertEquals(setOf("CalmRiver", "BrightStone"), setOf(aliases.getValue(first.key), aliases.getValue(second.key)))
        assertEquals("CalmRiver", aliases.getValue(otherNamespace.key))
    }

    @Test
    fun `tombstoned aliases are never reused`() {
        val key = AliasRequest(RegistryKey("pkg.Replacement", SymbolKind.CLASS, "Lpkg/Replacement;"), "pkg")
        val registry = PseudowordRegistry(
            lineageSeed = seed,
            tombstones = setOf(AliasTombstone("pkg", SymbolKind.CLASS, "CalmRiver")),
            candidateFactory = { _, probe -> if (probe == 0) "CalmRiver" else "BrightStone" },
        )

        assertEquals("BrightStone", registry.reconcile(listOf(key), generation = 1).getValue(key.key))
    }

    @Test
    fun `reserved and tombstoned names are skipped in a scoped namespace`() {
        val namespace = AliasNamespace("code-members-v2", SymbolKind.MEMBER)
        val request = AliasRequest(
            RegistryKey("com/example/Owner#binding", SymbolKind.MEMBER, "Ljava/lang/Object;"),
            namespace.namespace,
        )
        val registry = PseudowordRegistry(
            lineageSeed = seed,
            tombstones = setOf(AliasTombstone(namespace.namespace, SymbolKind.MEMBER, "calmHarbor")),
            candidateFactory = { _, probe -> listOf("amberRiver", "calmHarbor", "gentleMeadow")[probe] },
        )

        val aliases = registry.reconcileScoped(
            requests = listOf(request),
            generation = 2,
            kinds = setOf(SymbolKind.MEMBER),
            reservedAliases = mapOf(namespace to setOf("amberRiver")),
        )

        assertEquals("gentleMeadow", aliases.values.single())
    }

    @Test
    fun `reserved aliases reject invalid scopes shapes and persisted conflicts`() {
        val request = AliasRequest(RegistryKey("pkg.Owner#value", SymbolKind.MEMBER, "I"), "code-members-v2")
        val registry = PseudowordRegistry(seed, candidateFactory = { _, _ -> "calmHarbor" })
        registry.reconcileScoped(listOf(request), 1, setOf(SymbolKind.MEMBER))

        assertFailsWith<IllegalArgumentException> {
            registry.reconcileScoped(
                listOf(request),
                2,
                setOf(SymbolKind.MEMBER),
                mapOf(AliasNamespace("code-members-v2", SymbolKind.CLASS) to setOf("CalmHarbor")),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            registry.reconcileScoped(
                listOf(request),
                2,
                setOf(SymbolKind.MEMBER),
                mapOf(AliasNamespace("code-members-v2", SymbolKind.MEMBER) to setOf("NotMember")),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            registry.reconcileScoped(
                listOf(request),
                2,
                setOf(SymbolKind.MEMBER),
                mapOf(AliasNamespace("code-members-v2", SymbolKind.MEMBER) to setOf("calmHarbor")),
            )
        }
    }

    @Test
    fun `reconcile is independent of request order`() {
        val requests = listOf(
            AliasRequest(RegistryKey("pkg.Third", SymbolKind.CLASS, "Lpkg/Third;"), "pkg"),
            AliasRequest(RegistryKey("pkg.First", SymbolKind.CLASS, "Lpkg/First;"), "pkg"),
            AliasRequest(RegistryKey("pkg.Second#call", SymbolKind.MEMBER, "()V"), "pkg.Second"),
        )
        val first = PseudowordRegistry(seed)
        val second = PseudowordRegistry(seed)

        val firstResult = first.reconcile(requests, generation = 1)
        val secondResult = second.reconcile(requests.reversed(), generation = 1)

        assertEquals(firstResult, secondResult)
        assertEquals(first.snapshot(generation = 1), second.snapshot(generation = 1))
    }

    @Test
    fun `snapshot reuse removal tombstone and restoration are generation aware`() {
        val firstRequest = AliasRequest(RegistryKey("pkg.First", SymbolKind.CLASS, "Lpkg/First;"), "pkg")
        val secondRequest = AliasRequest(RegistryKey("pkg.Second", SymbolKind.CLASS, "Lpkg/Second;"), "pkg")
        val registry = PseudowordRegistry(seed)
        val generationOne = registry.reconcile(listOf(firstRequest, secondRequest), generation = 1)
        val originalAlias = generationOne.getValue(firstRequest.key)
        val persisted = registry.snapshot(generation = 1)

        val reloaded = PseudowordRegistry.restore(seed, persisted)
        assertEquals(
            originalAlias,
            reloaded.reconcile(listOf(firstRequest, secondRequest), generation = 1).getValue(firstRequest.key),
        )
        reloaded.reconcile(listOf(secondRequest), generation = 2)
        val tombstone = reloaded.snapshot(generation = 2).tombstones.single()

        assertEquals(originalAlias, tombstone.alias)
        assertEquals(SymbolKind.CLASS, tombstone.kind)
        assertEquals("pkg", tombstone.namespace)
        assertEquals(64, tombstone.keyHash.length)
        assertEquals(2, tombstone.retiredGeneration)

        val restored = reloaded.reconcile(listOf(firstRequest, secondRequest), generation = 3)
        assertNotEquals(originalAlias, restored.getValue(firstRequest.key))
    }

    @Test
    fun `registry JSON round trips assignments tombstones and seed identity`() {
        val first = AliasRequest(RegistryKey("pkg.First", SymbolKind.CLASS, "Lpkg/First;"), "pkg")
        val second = AliasRequest(RegistryKey("pkg.Second", SymbolKind.CLASS, "Lpkg/Second;"), "pkg")
        val registry = PseudowordRegistry(seed)
        registry.reconcile(listOf(first, second), generation = 1)
        registry.reconcile(listOf(second), generation = 2)
        val snapshot = registry.snapshot(generation = 2)
        val codec = RegistryCodec()

        assertEquals(snapshot, codec.decode(codec.encode(snapshot)))
        assertEquals(64, snapshot.seedSha256.length)
        assertTrue(codec.encode(snapshot).endsWith("\n"))
    }

    @Test
    fun `restore rejects duplicate registry identities and alias collisions`() {
        val first = AliasRequest(RegistryKey("pkg.First", SymbolKind.CLASS, "Lpkg/First;"), "pkg")
        val second = AliasRequest(RegistryKey("pkg.Second", SymbolKind.CLASS, "Lpkg/Second;"), "pkg")
        val registry = PseudowordRegistry(seed)
        registry.reconcile(listOf(first, second), generation = 1)
        val snapshot = registry.snapshot(generation = 1)

        assertFailsWith<IllegalArgumentException> {
            PseudowordRegistry.restore(seed, snapshot.copy(assignments = snapshot.assignments + snapshot.assignments.first()))
        }
        assertFailsWith<IllegalArgumentException> {
            PseudowordRegistry.restore(
                seed,
                snapshot.copy(
                    assignments = listOf(
                        snapshot.assignments[0],
                        snapshot.assignments[1].copy(alias = snapshot.assignments[0].alias),
                    ),
                ),
            )
        }
    }

    @Test
    fun `restore rejects corrupt tombstones and assignment conflicts`() {
        val request = AliasRequest(RegistryKey("pkg.First", SymbolKind.CLASS, "Lpkg/First;"), "pkg")
        val registry = PseudowordRegistry(seed)
        registry.reconcile(listOf(request), generation = 1)
        val snapshot = registry.snapshot(generation = 1)
        val assignment = snapshot.assignments.single()
        val conflicting = AliasTombstone(
            namespace = assignment.namespace,
            kind = assignment.key.kind,
            alias = assignment.alias,
            keyHash = "a".repeat(64),
            retiredGeneration = 1,
        )

        assertFailsWith<IllegalArgumentException> {
            PseudowordRegistry.restore(seed, snapshot.copy(tombstones = listOf(conflicting)))
        }
        assertFailsWith<IllegalArgumentException> {
            PseudowordRegistry.restore(seed, snapshot.copy(tombstones = listOf(conflicting.copy(alias = "not-valid", retiredGeneration = 0))))
        }
        assertFailsWith<IllegalArgumentException> {
            PseudowordRegistry.restore(seed, snapshot.copy(tombstones = listOf(conflicting, conflicting)))
        }
    }

    @Test
    fun `restore preserves multiple retirements of the same identity`() {
        val request = AliasRequest(RegistryKey("pkg.First", SymbolKind.CLASS, "Lpkg/First;"), "pkg")
        val registry = PseudowordRegistry(seed)
        val firstAlias = registry.reconcile(listOf(request), generation = 1).getValue(request.key)
        registry.reconcile(emptyList(), generation = 2)
        val secondAlias = registry.reconcile(listOf(request), generation = 3).getValue(request.key)
        registry.reconcile(emptyList(), generation = 4)
        val snapshot = registry.snapshot(generation = 4)

        assertNotEquals(firstAlias, secondAlias)
        assertEquals(2, snapshot.tombstones.size)
        assertEquals(1, snapshot.tombstones.map(AliasTombstone::keyHash).distinct().size)
        assertEquals(snapshot, PseudowordRegistry.restore(seed, snapshot).snapshot(generation = 4))
    }
}
