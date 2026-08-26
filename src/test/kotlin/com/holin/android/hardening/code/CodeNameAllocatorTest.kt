package com.holin.android.hardening.code

import com.holin.android.hardening.naming.AliasRequest
import com.holin.android.hardening.naming.PseudowordRegistry
import com.holin.android.hardening.naming.RegistrySnapshot
import com.holin.android.hardening.naming.SymbolKind
import com.holin.android.hardening.state.Sha256
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import org.objectweb.asm.Opcodes

class CodeNameAllocatorTest {
    private val seed = Sha256.digest("code-name-lineage".toByteArray())

    @Test
    fun `new Bean policy retires only legacy field assignments and preserves class and method aliases`() {
        val ownerName = "com/example/Profile"
        val value = field(ownerName, "id", "J")
        val refresh = method(ownerName, "refresh", "()V")
        val owner = type(ownerName, fields = listOf(value), methods = listOf(refresh))
        val bytecode = bytecode(listOf(owner))
        val first = CodeNameAllocator(registry()).allocate(
            namingInventory(classEligible(owner), fieldEligible(value), methodEligible(refresh)),
            bytecode,
            1,
        )
        val legacyFieldKey = fieldKey(value)
        val legacyFieldAssignment = first.registry.assignments.single {
            it.key.originalIdentity == fieldRegistryIdentity(legacyFieldKey)
        }
        val previousClassAlias = first.assignments.single { it.key == classKey(owner) }.alias
        val previousMethodAlias = first.assignments.single { it.key == methodKey(refresh) }.alias

        val protected = PotentialBeanField(":app", legacyFieldKey, value.access)
        val second = CodeNameAllocator(PseudowordRegistry.restore(seed, first.registry)).allocate(
            CodeNamingInventory(
                listOf(classEligible(owner), methodEligible(refresh)),
                PotentialBeanFieldPolicy().exclusions(listOf(protected)),
            ),
            bytecode,
            2,
        )

        assertFalse(second.assignments.any { it.key == legacyFieldKey })
        assertTrue(second.registry.tombstones.any { it.keyHash == legacyFieldAssignment.keyHash })
        assertEquals(previousClassAlias, second.assignments.single { it.key == classKey(owner) }.alias)
        assertEquals(previousMethodAlias, second.assignments.single { it.key == methodKey(refresh) }.alias)
        assertEquals(first.registry.seedSha256, second.registry.seedSha256)
    }

    @Test
    fun `owned override declarations share one non reserved global member alias`() {
        val base = type("com/example/Base", methods = listOf(method("com/example/Base", "render", "(Ljava/lang/String;)V")))
        val child = type(
            "com/example/Child",
            superName = base.internalName,
            methods = listOf(method("com/example/Child", "render", "(Ljava/lang/String;)V")),
        )
        val dependency = type("third/Api", methods = listOf(method("third/Api", "amberRiver", "()V")))
        val bytecode = bytecode(listOf(base, child), listOf(dependency))
        val group = OverrideGraphBuilder().build(bytecode).single { it.members.size == 2 }
        val inventory = namingInventory(
            classEligible(base),
            classEligible(child),
            methodEligible(base.methods.single(), group.id),
            methodEligible(child.methods.single(), group.id),
        )
        val plan = CodeNameAllocator(registry()).allocate(inventory, bytecode, generation = 1)
        val methods = plan.assignments.filter { it.key.kind == CodeSymbolKind.METHOD }

        assertEquals(2, methods.size)
        assertEquals(setOf("calmHarbor"), methods.map(AssignedCodeName::alias).toSet())
        assertEquals(1, plan.registry.assignments.count { it.key.kind == SymbolKind.MEMBER })
        assertFalse(plan.assignments.any { it.key.owner == dependency.internalName })
    }

    @Test
    fun `persisted override groups fail closed when different aliases merge`() {
        val base = type(
            "com/example/Able",
            methods = listOf(method("com/example/Able", "render", "()V")),
        )
        val standalone = type(
            "com/example/Zed",
            methods = listOf(method("com/example/Zed", "render", "()V")),
        )
        val firstBytecode = bytecode(listOf(base, standalone))
        val firstGroups = OverrideGraphBuilder().build(firstBytecode).associateBy { it.members.single().owner }
        val registry = registry()
        val allocator = CodeNameAllocator(registry)
        allocator.allocate(
            namingInventory(
                methodEligible(base.methods.single(), firstGroups.getValue(base.internalName).id),
                methodEligible(standalone.methods.single(), firstGroups.getValue(standalone.internalName).id),
            ),
            firstBytecode,
            1,
        )

        val child = type(
            "com/example/Zed",
            superName = base.internalName,
            methods = listOf(method("com/example/Zed", "render", "()V")),
        )
        val mergedBytecode = bytecode(listOf(base, child))
        val merged = OverrideGraphBuilder().build(mergedBytecode).single { it.members.size == 2 }
        val failure = assertFailsWith<IllegalArgumentException> {
            allocator.allocate(
                namingInventory(
                    methodEligible(base.methods.single(), merged.id),
                    methodEligible(child.methods.single(), merged.id),
                ),
                mergedBytecode,
                2,
            )
        }

        assertTrue(failure.message.orEmpty().contains("persisted override groups merge"))
    }

    @Test
    fun `override family keeps its sole prior alias when the minimum member changes`() {
        val standalone = type(
            "com/example/Zed",
            methods = listOf(method("com/example/Zed", "render", "()V")),
        )
        val firstBytecode = bytecode(listOf(standalone))
        val firstGroup = OverrideGraphBuilder().build(firstBytecode).single()
        val allocator = CodeNameAllocator(registry())
        val first = allocator.allocate(
            namingInventory(methodEligible(standalone.methods.single(), firstGroup.id)),
            firstBytecode,
            1,
        )

        val base = type(
            "com/example/Able",
            methods = listOf(method("com/example/Able", "render", "()V")),
        )
        val child = type(
            "com/example/Zed",
            superName = base.internalName,
            methods = listOf(method("com/example/Zed", "render", "()V")),
        )
        val extendedBytecode = bytecode(listOf(base, child))
        val extendedGroup = OverrideGraphBuilder().build(extendedBytecode).single { it.members.size == 2 }
        val extended = allocator.allocate(
            namingInventory(
                methodEligible(base.methods.single(), extendedGroup.id),
                methodEligible(child.methods.single(), extendedGroup.id),
            ),
            extendedBytecode,
            2,
        )
        val removedMinimumBytecode = bytecode(listOf(standalone))
        val removedMinimumGroup = OverrideGraphBuilder().build(removedMinimumBytecode).single()
        val removedMinimum = allocator.allocate(
            namingInventory(methodEligible(standalone.methods.single(), removedMinimumGroup.id)),
            removedMinimumBytecode,
            3,
        )

        assertEquals(first.assignments.single().alias, extended.assignments.first().alias)
        assertEquals(first.assignments.single().alias, removedMinimum.assignments.single().alias)
        assertEquals(1, removedMinimum.registry.assignments.count { it.key.kind == SymbolKind.MEMBER })
        assertTrue(removedMinimum.registry.tombstones.none { it.alias == first.assignments.single().alias })
    }

    @Test
    fun `overload descriptors receive distinct aliases in one global namespace`() {
        val owner = type(
            "com/example/Overloads",
            methods = listOf(method("com/example/Overloads", "set", "(I)V"), method("com/example/Overloads", "set", "([J)V")),
        )
        val plan = CodeNameAllocator(registry()).allocate(
            namingInventory(classEligible(owner), owner.methods.map { methodEligible(it) }),
            bytecode(listOf(owner)),
            1,
        )

        assertEquals(2, plan.assignments.filter { it.key.kind == CodeSymbolKind.METHOD }.map(AssignedCodeName::alias).distinct().size)
    }

    @Test
    fun `eligible method override ids must exactly match the recomputed graph`() {
        val base = type("com/example/Base", methods = listOf(method("com/example/Base", "render", "()V")))
        val child = type(
            "com/example/Child",
            superName = base.internalName,
            methods = listOf(method("com/example/Child", "render", "()V")),
        )
        val overridingBytecode = bytecode(listOf(base, child))
        assertFailsWith<IllegalArgumentException> {
            CodeNameAllocator(registry()).allocate(
                namingInventory(methodEligible(base.methods.single(), null), methodEligible(child.methods.single(), null)),
                overridingBytecode,
                1,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            CodeNameAllocator(registry()).allocate(
                namingInventory(methodEligible(base.methods.single(), "forged"), methodEligible(child.methods.single(), "forged")),
                overridingBytecode,
                1,
            )
        }

        val unrelated = type(
            "com/example/Unrelated",
            methods = listOf(method("com/example/Unrelated", "left", "()V"), method("com/example/Unrelated", "right", "()V")),
        )
        assertFailsWith<IllegalArgumentException> {
            CodeNameAllocator(registry()).allocate(
                namingInventory(
                    methodEligible(unrelated.methods[0], "shared-forged-id"),
                    methodEligible(unrelated.methods[1], "shared-forged-id"),
                ),
                bytecode(listOf(unrelated)),
                1,
            )
        }
    }

    @Test
    fun `package and class candidates skip visible hierarchy collisions`() {
        val owner = type("com/example/Owner")
        val hierarchy = listOf(
            type("reservedroot"),
            type("safeharbor/reservedsegment"),
            type("safeharbor/quietmeadow/ReservedClass"),
        )
        val candidateFactory: (AliasRequest, Int) -> String = { request, probe ->
            when (request.key.kind) {
                SymbolKind.PACKAGE -> when (request.key.originalIdentity) {
                    "com" -> listOf("reservedroot", "safeharbor")[probe]
                    "com/example" -> listOf("reservedsegment", "quietmeadow")[probe]
                    else -> error("unexpected package ${request.key.originalIdentity}")
                }
                SymbolKind.CLASS -> listOf("ReservedClass", "SafeClass")[probe]
                else -> error("unexpected candidate request")
            }
        }
        val plan = CodeNameAllocator(PseudowordRegistry(seed, candidateFactory = candidateFactory)).allocate(
            namingInventory(classEligible(owner)),
            bytecode(listOf(owner), hierarchy),
            1,
        )

        assertEquals("safeharbor/quietmeadow/SafeClass", plan.assignments.single().outputOwner)
    }

    @Test
    fun `package class and member candidates skip case folded hierarchy collisions`() {
        val call = method("com/Owner", "call", "()V")
        val owner = type("com/Owner", methods = listOf(call))
        val hierarchy = listOf(
            type("SAFEROOT"),
            type("SafeHarbor/ReservedClass"),
            type("third/Api", methods = listOf(method("third/Api", "calmharbor", "()V"))),
        )
        val candidateFactory: (AliasRequest, Int) -> String = { request, probe ->
            when (request.key.kind) {
                SymbolKind.PACKAGE -> listOf("saferoot", "safeharbor")[probe]
                SymbolKind.CLASS -> listOf("ReservedClass", "SafeClass")[probe]
                SymbolKind.MEMBER -> listOf("calmHarbor", "gentleMeadow")[probe]
                SymbolKind.RESOURCE -> error("unexpected resource request")
            }
        }
        val plan = CodeNameAllocator(PseudowordRegistry(seed, candidateFactory = candidateFactory)).allocate(
            namingInventory(classEligible(owner), methodEligible(call)),
            bytecode(listOf(owner), hierarchy),
            1,
        )

        assertEquals("safeharbor/SafeClass", plan.assignments.single { it.key.kind == CodeSymbolKind.CLASS }.outputOwner)
        assertEquals("gentleMeadow", plan.assignments.single { it.key.kind == CodeSymbolKind.METHOD }.alias)
    }

    @Test
    fun `class output skips a case folded collision with a planned child package`() {
        val parentOwner = type("com/Owner")
        val childOwner = type("com/child/Child")
        val candidateFactory: (AliasRequest, Int) -> String = { request, probe ->
            when (request.key.kind) {
                SymbolKind.PACKAGE -> when (request.key.originalIdentity) {
                    "com" -> "safeharbor"
                    "com/child" -> "quietmeadow"
                    else -> error("unexpected package ${request.key.originalIdentity}")
                }
                SymbolKind.CLASS -> listOf("Quietmeadow", "SafeClass")[probe]
                else -> error("unexpected candidate request")
            }
        }
        val plan = CodeNameAllocator(PseudowordRegistry(seed, candidateFactory = candidateFactory)).allocate(
            namingInventory(classEligible(parentOwner), classEligible(childOwner)),
            bytecode(listOf(parentOwner, childOwner)),
            1,
        )

        assertEquals(
            "safeharbor/SafeClass",
            plan.assignments.single { it.key.owner == parentOwner.internalName }.outputOwner,
        )
    }

    @Test
    fun `package prefixes are shared while sibling segments receive distinct stable aliases`() {
        val first = type("com/example/First")
        val second = type("com/other/Second")
        val plan = CodeNameAllocator(registry()).allocate(
            namingInventory(classEligible(first), classEligible(second)),
            bytecode(listOf(first, second)),
            1,
        )
        val outputPackages = plan.assignments.map { it.outputOwner.substringBeforeLast('/') }

        assertEquals(1, outputPackages.map { it.substringBefore('/') }.distinct().size)
        assertEquals(2, outputPackages.map { it.substringAfter('/') }.distinct().size)
        assertEquals(3, plan.registry.assignments.count { it.key.kind == SymbolKind.PACKAGE })
    }

    @Test
    fun `unchanged package prefixes remain stable without transient tombstones across generations`() {
        val owner = type("com/example/Owner")
        val allocator = CodeNameAllocator(registry())
        val inventory = namingInventory(classEligible(owner))
        val bytecode = bytecode(listOf(owner))

        val first = allocator.allocate(inventory, bytecode, 1)
        val second = allocator.allocate(inventory, bytecode, 2)

        assertEquals(first.assignments.map { it.copy() }, second.assignments)
        assertTrue(second.registry.tombstones.isEmpty())
    }

    @Test
    fun `removed names are tombstoned and a revived symbol gets a fresh alias`() {
        val owner = type("com/example/Owner")
        val registry = registry()
        val allocator = CodeNameAllocator(registry)
        val first = allocator.allocate(namingInventory(classEligible(owner)), bytecode(listOf(owner)), 1)
        val firstOutput = first.assignments.single().outputOwner
        allocator.allocate(namingInventory(), bytecode(listOf(owner)), 2)
        val revived = allocator.allocate(namingInventory(classEligible(owner)), bytecode(listOf(owner)), 3)

        assertNotEquals(firstOutput, revived.assignments.single().outputOwner)
        assertTrue(revived.registry.tombstones.any { tombstone -> firstOutput.split('/').contains(tombstone.alias) })
    }

    @Test
    fun `constructors and exclusions are never assigned while members of a preserved class remain eligible`() {
        val constructor = method("com/example/Owner", "<init>", "()V")
        val call = method("com/example/Owner", "call", "()V")
        val owner = type("com/example/Owner", methods = listOf(constructor, call))
        val classKey = classKey(owner)
        val inventory = CodeNamingInventory(
            eligible = listOf(methodEligible(call)),
            exclusions = listOf(
                CodeExclusion(classKey, CodeExclusionReason.JNI_NATIVE, "preserved owner"),
                CodeExclusion(methodKey(constructor), CodeExclusionReason.CONSTRUCTOR, "constructor"),
            ),
        )
        val plan = CodeNameAllocator(registry()).allocate(inventory, bytecode(listOf(owner)), 1)

        assertEquals(listOf("call"), plan.assignments.map { it.key.name })
        assertEquals(owner.internalName, plan.assignments.single().outputOwner)
        assertEquals(inventory.exclusions.toSet(), plan.exclusions.toSet())
        assertFailsWith<IllegalArgumentException> {
            CodeNameAllocator(registry()).allocate(
                namingInventory(EligibleCodeSymbol(methodKey(constructor), null)),
                bytecode(listOf(owner)),
                1,
            )
        }
    }

    @Test
    fun `eligible classes stay in the original package when a sibling class name is preserved`() {
        val preserved = type("com/example/SplashActivity")
        val synthetic = type("com/example/SplashActivity\$sam\$Observer\$0")
        val inventory = CodeNamingInventory(
            listOf(classEligible(synthetic)),
            listOf(
                CodeExclusion(
                    classKey(preserved),
                    CodeExclusionReason.MANIFEST_DECLARED_CLASS,
                    "launcher activity name is externally preserved",
                ),
            ),
        )

        val plan = CodeNameAllocator(registry()).allocate(
            inventory,
            bytecode(listOf(preserved, synthetic)),
            1,
        )
        val assignment = plan.assignments.single()

        assertEquals("com/example", assignment.outputOwner.substringBeforeLast('/'))
        assertNotEquals(synthetic.internalName, assignment.outputOwner)
        assertTrue(plan.registry.assignments.none { it.key.kind == SymbolKind.PACKAGE })
    }

    @Test
    fun `dependency symbols and inconsistent inventory are rejected`() {
        val owner = type("com/example/Owner")
        val dependency = type("third/Api", methods = listOf(method("third/Api", "call", "()V")))
        val bytecode = bytecode(listOf(owner), listOf(dependency))

        assertFailsWith<IllegalArgumentException> {
            CodeNameAllocator(registry()).allocate(namingInventory(classEligible(dependency)), bytecode, 1)
        }
        val falselyOwnedDependency = BytecodeInventory(
            mapOf(dependency.internalName to dependency),
            mapOf(dependency.internalName to dependency),
        )
        assertFailsWith<IllegalArgumentException> {
            CodeNameAllocator(registry()).allocate(
                namingInventory(classEligible(dependency)),
                falselyOwnedDependency,
                1,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            CodeNameAllocator(registry()).allocate(
                namingInventory(EligibleCodeSymbol(CodeSymbolKey(CodeSymbolKind.FIELD, owner.internalName, "missing", "I"), null)),
                bytecode,
                1,
            )
        }
    }

    @Test
    fun `allocation is deterministic and plan collections are immutable`() {
        val first = type("com/example/First", fields = listOf(field("com/example/First", "count", "I")))
        val second = type("com/example/Second", methods = listOf(method("com/example/Second", "work", "()V")))
        val eligible = listOf(classEligible(first), fieldEligible(first.fields.single()), classEligible(second), methodEligible(second.methods.single()))
        val exclusion = CodeExclusion(methodKey(method("com/example/Second", "<init>", "()V")), CodeExclusionReason.CONSTRUCTOR, "constructor")
        val firstPlan = CodeNameAllocator(registry()).allocate(
            CodeNamingInventory(eligible, listOf(exclusion)),
            bytecode(listOf(first, second)),
            1,
        )
        val secondPlan = CodeNameAllocator(registry()).allocate(
            CodeNamingInventory(eligible.reversed(), listOf(exclusion)),
            bytecode(listOf(second, first)),
            1,
        )

        assertEquals(firstPlan, secondPlan)
        assertFailsWith<UnsupportedOperationException> { (firstPlan.assignments as MutableList).clear() }
        assertFailsWith<UnsupportedOperationException> { (firstPlan.exclusions as MutableList).clear() }
        assertFailsWith<UnsupportedOperationException> { (firstPlan.registry.assignments as MutableList).clear() }
        val mutableAssignments = firstPlan.registry.assignments.toMutableList()
        val mutableTombstones = firstPlan.registry.tombstones.toMutableList()
        val copied = testCodeNamePlan(
            firstPlan.assignments,
            firstPlan.exclusions,
            firstPlan.registry.copy(assignments = mutableAssignments, tombstones = mutableTombstones),
            firstPlan.ownedOriginalOwners,
        )
        mutableAssignments.clear()
        mutableTombstones.clear()
        assertEquals(firstPlan.registry, copied.registry)
        assertFailsWith<UnsupportedOperationException> { (copied.registry.assignments as MutableList).clear() }
        assertFailsWith<UnsupportedOperationException> { (copied.registry.tombstones as MutableList).clear() }
        assertFailsWith<UnsupportedOperationException> { (copied.ownedOriginalOwners as MutableSet).clear() }
    }

    private fun registry(): PseudowordRegistry = PseudowordRegistry(
        lineageSeed = seed,
        candidateFactory = { request, probe ->
            when (request.key.kind) {
                SymbolKind.PACKAGE -> listOf("quietmeadow", "gentleharbor", "tidalriver")[probe]
                SymbolKind.CLASS -> listOf("QuietMeadow", "GentleHarbor", "TidalRiver")[probe]
                SymbolKind.MEMBER -> listOf("amberRiver", "calmHarbor", "gentleMeadow", "tidalRiver")[probe]
                SymbolKind.RESOURCE -> error("unexpected resource request")
            }
        },
    )

    private fun testCodeNamePlan(
        assignments: Collection<AssignedCodeName>,
        exclusions: Collection<CodeExclusion>,
        registry: RegistrySnapshot,
        ownedOriginalOwners: Collection<String>,
    ): CodeNamePlan {
        val constructor = Class.forName("com.holin.android.hardening.code.ImmutableCodeNamePlan").getDeclaredConstructor(
            Collection::class.java,
            Collection::class.java,
            RegistrySnapshot::class.java,
            Collection::class.java,
        )
        constructor.isAccessible = true
        return constructor.newInstance(assignments, exclusions, registry, ownedOriginalOwners) as CodeNamePlan
    }

    private fun namingInventory(vararg eligible: Any): CodeNamingInventory {
        val flattened = eligible.flatMap { value ->
            when (value) {
                is EligibleCodeSymbol -> listOf(value)
                is Collection<*> -> value.filterIsInstance<EligibleCodeSymbol>()
                else -> error("unexpected fixture $value")
            }
        }
        return CodeNamingInventory(flattened, emptyList())
    }

    private fun classEligible(owner: BytecodeClass) = EligibleCodeSymbol(classKey(owner), null)
    private fun fieldEligible(value: BytecodeField) = EligibleCodeSymbol(fieldKey(value), null)
    private fun methodEligible(
        value: BytecodeMethod,
        group: String? = methodKey(value).canonicalIdentity,
    ) = EligibleCodeSymbol(methodKey(value), group)

    private fun bytecode(owned: List<BytecodeClass>, hierarchy: List<BytecodeClass> = emptyList()): BytecodeInventory {
        val all = (owned + hierarchy).associateBy(BytecodeClass::internalName)
        return BytecodeInventory(owned.associateBy(BytecodeClass::internalName), all)
    }

    private fun type(
        name: String,
        superName: String? = "java/lang/Object",
        fields: List<BytecodeField> = emptyList(),
        methods: List<BytecodeMethod> = emptyList(),
    ) = BytecodeClass(name, if (name.startsWith("com/")) ":app" else null, null, null, Opcodes.ACC_PUBLIC, superName,
        emptyList(), emptySet(), fields, methods)

    private fun field(owner: String, name: String, descriptor: String) = BytecodeField(owner, name, descriptor, Opcodes.ACC_PUBLIC, emptySet())
    private fun method(owner: String, name: String, descriptor: String) = BytecodeMethod(owner, name, descriptor, Opcodes.ACC_PUBLIC, emptySet())
}
