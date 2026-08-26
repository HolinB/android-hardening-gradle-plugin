package com.holin.android.hardening.code

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import org.objectweb.asm.Opcodes

class OverrideGraphTest {
    @Test
    fun `owned override shares a group while external dispatch is excluded`() {
        val base = type("com/example/Base", methods = listOf(method("com/example/Base", "render", "()V")))
        val child = type(
            "com/example/Child",
            superName = base.internalName,
            methods = listOf(method("com/example/Child", "render", "()V"), method("com/example/Child", "run", "()V")),
        )
        val runnable = type(
            "java/lang/Runnable",
            methods = listOf(method("java/lang/Runnable", "run", "()V", Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT)),
        )
        val inventory = inventory(listOf(base, child), listOf(runnable), childInterfaces = listOf(runnable.internalName))

        val groups = OverrideGraphBuilder().build(inventory)

        assertEquals(
            setOf("com/example/Base#render()V", "com/example/Child#render()V"),
            groups.single { !it.touchesExternal && it.members.any { member -> member.name == "render" } }
                .members.mapTo(sortedSetOf(), CodeSymbolKey::canonicalIdentity),
        )
        assertTrue(groups.single { it.members.any { member -> member.name == "run" } }.touchesExternal)
    }

    @Test
    fun `covariant implementation bridge joins its target and external declaration`() {
        val factory = type(
            "third/Factory",
            methods = listOf(method("third/Factory", "create", "()Ljava/lang/Object;", Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT)),
        )
        val value = type("com/example/Value", superName = "java/lang/Object")
        val implementation = type(
            "com/example/FactoryImpl",
            interfaces = listOf(factory.internalName),
            methods = listOf(
                method("com/example/FactoryImpl", "create", "()Lcom/example/Value;"),
                method(
                    "com/example/FactoryImpl",
                    "create",
                    "()Ljava/lang/Object;",
                    Opcodes.ACC_PUBLIC or Opcodes.ACC_BRIDGE or Opcodes.ACC_SYNTHETIC,
                ),
            ),
        )
        val inventory = inventory(listOf(value, implementation), listOf(factory, objectType()))

        val group = OverrideGraphBuilder().build(inventory).single { it.members.any { member -> member.owner == factory.internalName } }

        assertTrue(group.touchesExternal)
        assertEquals(3, group.members.size)
        assertTrue(group.members.any { it.descriptor == "()Lcom/example/Value;" })
    }

    @Test
    fun `erased parameter bridge joins its narrowed implementation target`() {
        val consumer = type(
            "third/Consumer",
            methods = listOf(method("third/Consumer", "accept", "(Ljava/lang/Object;)V", Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT)),
        )
        val implementation = type(
            "com/example/StringConsumer",
            interfaces = listOf(consumer.internalName),
            methods = listOf(
                method("com/example/StringConsumer", "accept", "(Ljava/lang/String;)V"),
                method(
                    "com/example/StringConsumer",
                    "accept",
                    "(Ljava/lang/Object;)V",
                    Opcodes.ACC_PUBLIC or Opcodes.ACC_BRIDGE or Opcodes.ACC_SYNTHETIC,
                ),
            ),
        )

        val group = OverrideGraphBuilder().build(inventory(listOf(implementation), listOf(consumer, objectType())))
            .single { it.members.any { member -> member.owner == consumer.internalName } }

        assertEquals(3, group.members.size)
        assertTrue(group.members.any { it.descriptor == "(Ljava/lang/String;)V" })
    }

    @Test
    fun `interface introduced by child connects an inherited concrete implementation`() {
        val runnable = type(
            "third/Runnable",
            access = Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT,
            methods = listOf(method("third/Runnable", "run", "()V", Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT)),
        )
        val base = type("com/example/Base", methods = listOf(method("com/example/Base", "run", "()V")))
        val child = type("com/example/Child", superName = base.internalName, interfaces = listOf(runnable.internalName))

        val group = OverrideGraphBuilder().build(inventory(listOf(base, child), listOf(runnable, objectType())))
            .single { it.members.any { member -> member.owner == base.internalName && member.name == "run" } }

        assertTrue(group.touchesExternal)
        assertEquals(setOf("com/example/Base#run()V", "third/Runnable#run()V"), group.members.mapTo(sortedSetOf()) { it.canonicalIdentity })
    }

    @Test
    fun `interface introduced by child connects an inherited abstract implementation`() {
        val task = type(
            "third/Task",
            access = Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT,
            methods = listOf(method("third/Task", "execute", "()V", Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT)),
        )
        val base = type(
            "com/example/AbstractBase",
            access = Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT,
            methods = listOf(method("com/example/AbstractBase", "execute", "()V", Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT)),
        )
        val child = type("com/example/AbstractChild", superName = base.internalName, interfaces = listOf(task.internalName), access = Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT)

        val group = OverrideGraphBuilder().build(inventory(listOf(base, child), listOf(task, objectType())))
            .single { it.members.any { member -> member.owner == base.internalName && member.name == "execute" } }

        assertTrue(group.touchesExternal)
        assertEquals(2, group.members.size)
    }

    @Test
    fun `inherited interface default connects to a separately inherited external contract`() {
        val localDefault = type(
            "com/example/LocalDefault",
            access = Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT,
            methods = listOf(method("com/example/LocalDefault", "label", "()Ljava/lang/String;")),
        )
        val externalContract = type(
            "third/Labelled",
            access = Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT,
            methods = listOf(method("third/Labelled", "label", "()Ljava/lang/String;", Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT)),
        )
        val combined = type(
            "com/example/Combined",
            access = Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT,
            interfaces = listOf(localDefault.internalName, externalContract.internalName),
        )

        val group = OverrideGraphBuilder().build(inventory(listOf(localDefault, combined), listOf(externalContract, objectType())))
            .single { it.members.any { member -> member.owner == localDefault.internalName && member.name == "label" } }

        assertTrue(group.touchesExternal)
        assertEquals(2, group.members.size)
    }

    @Test
    fun `inherited private static protected and package methods do not satisfy public interface dispatch`() {
        val contract = type(
            "third/Visibility",
            access = Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT,
            methods = listOf("secret", "utility", "protectedCall", "packageCall").map { name ->
                method("third/Visibility", name, "()V", Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT)
            },
        )
        val base = type(
            "com/example/Base",
            methods = listOf(
                method("com/example/Base", "secret", "()V", Opcodes.ACC_PRIVATE),
                method("com/example/Base", "utility", "()V", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                method("com/example/Base", "protectedCall", "()V", Opcodes.ACC_PROTECTED),
                method("com/example/Base", "packageCall", "()V", 0),
            ),
        )
        val child = type("com/example/Child", superName = base.internalName, interfaces = listOf(contract.internalName))

        val groups = OverrideGraphBuilder().build(inventory(listOf(base, child), listOf(contract, objectType())))

        listOf("secret", "utility", "protectedCall", "packageCall").forEach { name ->
            assertFalse(groups.any { group ->
                group.members.any { it.owner == base.internalName && it.name == name } &&
                    group.members.any { it.owner == contract.internalName && it.name == name }
            }, name)
        }
    }

    @Test
    fun `multi-dimensional reference and primitive arrays narrow one component at a time`() {
        val factory = type(
            "third/ArrayFactory",
            access = Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT,
            methods = listOf(
                method("third/ArrayFactory", "references", "()[Ljava/lang/Object;", Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT),
                method("third/ArrayFactory", "primitives", "()[Ljava/lang/Object;", Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT),
            ),
        )
        val implementation = type(
            "com/example/ArrayFactoryImpl",
            interfaces = listOf(factory.internalName),
            methods = listOf(
                method("com/example/ArrayFactoryImpl", "references", "()[[Ljava/lang/String;"),
                method("com/example/ArrayFactoryImpl", "references", "()[Ljava/lang/Object;", Opcodes.ACC_PUBLIC or Opcodes.ACC_BRIDGE or Opcodes.ACC_SYNTHETIC),
                method("com/example/ArrayFactoryImpl", "primitives", "()[[I"),
                method("com/example/ArrayFactoryImpl", "primitives", "()[Ljava/lang/Object;", Opcodes.ACC_PUBLIC or Opcodes.ACC_BRIDGE or Opcodes.ACC_SYNTHETIC),
            ),
        )

        val groups = OverrideGraphBuilder().build(inventory(listOf(implementation), listOf(factory, objectType())))

        listOf("references", "primitives").forEach { name ->
            val group = groups.single { it.members.any { member -> member.owner == factory.internalName && member.name == name } }
            assertEquals(3, group.members.size, name)
        }
    }

    @Test
    fun `arrays implement JVM array supertypes but primitive arrays do not narrow to Object arrays`() {
        val contract = type(
            "third/ArrayContracts",
            access = Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT,
            methods = listOf(
                method("third/ArrayContracts", "asObject", "()Ljava/lang/Object;", Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT),
                method("third/ArrayContracts", "asCloneable", "()Ljava/lang/Cloneable;", Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT),
                method("third/ArrayContracts", "asSerializable", "()Ljava/io/Serializable;", Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT),
                method("third/ArrayContracts", "invalid", "()[Ljava/lang/Object;", Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT),
            ),
        )
        val implementation = type(
            "com/example/Arrays",
            interfaces = listOf(contract.internalName),
            methods = listOf(
                method("com/example/Arrays", "asObject", "()[I"),
                method("com/example/Arrays", "asCloneable", "()[I"),
                method("com/example/Arrays", "asSerializable", "()[I"),
                method("com/example/Arrays", "invalid", "()[I"),
            ),
        )

        val groups = OverrideGraphBuilder().build(inventory(listOf(implementation), listOf(contract, objectType())))

        listOf("asObject", "asCloneable", "asSerializable").forEach { name ->
            assertEquals(2, groups.single { it.members.any { member -> member.owner == contract.internalName && member.name == name } }.members.size)
        }
        assertFalse(groups.any { group ->
            group.members.any { it.owner == contract.internalName && it.name == "invalid" } &&
                group.members.any { it.owner == implementation.internalName && it.name == "invalid" }
        })
    }

    @Test
    fun `ambiguous erased bridge conservatively joins every variance-compatible target`() {
        val consumer = type(
            "third/Consumer",
            access = Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT,
            methods = listOf(method("third/Consumer", "accept", "(Ljava/lang/Object;)V", Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT)),
        )
        val stringType = type("java/lang/String")
        val integerType = type("java/lang/Integer")
        val implementation = type(
            "com/example/AmbiguousConsumer",
            interfaces = listOf(consumer.internalName),
            methods = listOf(
                method("com/example/AmbiguousConsumer", "accept", "(Ljava/lang/String;)V"),
                method("com/example/AmbiguousConsumer", "accept", "(Ljava/lang/Integer;)V"),
                method("com/example/AmbiguousConsumer", "accept", "(Ljava/lang/Object;)V", Opcodes.ACC_PUBLIC or Opcodes.ACC_BRIDGE or Opcodes.ACC_SYNTHETIC),
            ),
        )

        val group = OverrideGraphBuilder().build(inventory(listOf(implementation), listOf(consumer, stringType, integerType, objectType())))
            .single { it.members.any { member -> member.owner == consumer.internalName } }

        assertEquals(4, group.members.size)
        assertTrue(group.members.map { it.descriptor }.containsAll(listOf("(Ljava/lang/String;)V", "(Ljava/lang/Integer;)V")))
    }

    @Test
    fun `override graph outputs are immutable value objects`() {
        val key = CodeSymbolKey(CodeSymbolKind.METHOD, "com/example/Owner", "run", "()V")
        val original = linkedSetOf(key)
        val first = OverrideGroup("group", original, false)
        val equal = OverrideGroup("group", setOf(key), false)
        original.clear()

        assertEquals(setOf(key), first.members)
        assertEquals(equal, first)
        assertEquals(equal.hashCode(), first.hashCode())
        assertFailsWith<UnsupportedOperationException> { (first.members as MutableSet).clear() }

        val owner = type("com/example/Owner", methods = listOf(method("com/example/Owner", "run", "()V")))
        val groups = OverrideGraphBuilder().build(inventory(listOf(owner), listOf(objectType())))
        assertFailsWith<UnsupportedOperationException> { (groups as MutableList).clear() }
    }

    @Test
    fun `override groups are deterministic for all input permutations`() {
        val firstContract = type(
            "third/FirstContract",
            access = Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT,
            methods = listOf(method("third/FirstContract", "render", "()V", Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT)),
        )
        val secondContract = type(
            "third/SecondContract",
            access = Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT,
            methods = listOf(method("third/SecondContract", "other", "()V", Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT)),
        )
        val left = type(
            "com/example/Left",
            methods = listOf(method("com/example/Left", "render", "()V"), method("com/example/Left", "other", "()V")),
        )
        val right = type(
            "com/example/Right",
            superName = left.internalName,
            interfaces = listOf(firstContract.internalName, secondContract.internalName),
            methods = listOf(method("com/example/Right", "other", "()V"), method("com/example/Right", "render", "()V")),
        )
        val leftPermuted = type(
            "com/example/Left",
            methods = left.methods.reversed(),
        )
        val rightPermuted = type(
            "com/example/Right",
            superName = left.internalName,
            interfaces = right.interfaces.reversed(),
            methods = right.methods.reversed(),
        )
        val objectType = objectType()
        val first = BytecodeInventory(
            linkedMapOf(left.internalName to left, right.internalName to right),
            linkedMapOf(
                left.internalName to left,
                right.internalName to right,
                firstContract.internalName to firstContract,
                secondContract.internalName to secondContract,
                objectType.internalName to objectType,
            ),
        )
        val second = BytecodeInventory(
            linkedMapOf(rightPermuted.internalName to rightPermuted, leftPermuted.internalName to leftPermuted),
            linkedMapOf(
                objectType.internalName to objectType,
                secondContract.internalName to secondContract,
                firstContract.internalName to firstContract,
                rightPermuted.internalName to rightPermuted,
                leftPermuted.internalName to leftPermuted,
            ),
        )

        assertEquals(OverrideGraphBuilder().build(first), OverrideGraphBuilder().build(second))
    }

    @Test
    fun `interface default and implementing declarations share a group`() {
        val defaultApi = type(
            "com/example/DefaultApi",
            access = Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT,
            methods = listOf(method("com/example/DefaultApi", "label", "()Ljava/lang/String;")),
        )
        val implementation = type(
            "com/example/DefaultImpl",
            interfaces = listOf(defaultApi.internalName),
            methods = listOf(method("com/example/DefaultImpl", "label", "()Ljava/lang/String;")),
        )

        val group = OverrideGraphBuilder().build(inventory(listOf(defaultApi, implementation), listOf(objectType())))
            .single { it.members.any { member -> member.name == "label" } }

        assertFalse(group.touchesExternal)
        assertEquals(2, group.members.size)
    }

    @Test
    fun `private static package-invisible and parameter-incompatible methods do not override`() {
        val otherPackageParent = type(
            "other/Parent",
            methods = listOf(
                method("other/Parent", "hidden", "()V", 0),
                method("other/Parent", "secret", "()V", Opcodes.ACC_PRIVATE),
                method("other/Parent", "utility", "()V", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                method("other/Parent", "accept", "(Ljava/lang/String;)V"),
            ),
        )
        val child = type(
            "com/example/Child",
            superName = otherPackageParent.internalName,
            methods = listOf(
                method("com/example/Child", "hidden", "()V"),
                method("com/example/Child", "secret", "()V"),
                method("com/example/Child", "utility", "()V"),
                method("com/example/Child", "accept", "(Ljava/lang/Object;)V"),
            ),
        )

        val groups = OverrideGraphBuilder().build(inventory(listOf(child), listOf(otherPackageParent, objectType())))

        listOf("hidden", "secret", "utility", "accept").forEach { name ->
            val childGroup = groups.single { group -> group.members.any { it.owner == child.internalName && it.name == name } }
            assertEquals(1, childGroup.members.size, name)
        }
    }

    @Test
    fun `unrelated return types do not form an override group`() {
        val left = type("com/example/Left", superName = "java/lang/Object")
        val right = type("com/example/Right", superName = "java/lang/Object")
        val parent = type("com/example/Parent", methods = listOf(method("com/example/Parent", "value", "()Lcom/example/Left;")))
        val child = type(
            "com/example/Child",
            superName = parent.internalName,
            methods = listOf(method("com/example/Child", "value", "()Lcom/example/Right;")),
        )
        val groups = OverrideGraphBuilder().build(inventory(listOf(left, right, parent, child), listOf(objectType())))

        val parentId = groups.single { it.members.any { member -> member.owner == parent.internalName && member.name == "value" } }.id
        val childId = groups.single { it.members.any { member -> member.owner == child.internalName && member.name == "value" } }.id

        assertNotEquals(parentId, childId)
    }

    private fun inventory(
        owned: List<BytecodeClass>,
        external: List<BytecodeClass>,
        childInterfaces: List<String> = emptyList(),
    ): BytecodeInventory {
        val adjustedOwned = if (childInterfaces.isEmpty()) owned else owned.map { value ->
            if (value.internalName != "com/example/Child") value else type(
                value.internalName,
                superName = value.superName,
                interfaces = childInterfaces,
                methods = value.methods,
            )
        }
        val hierarchy = (adjustedOwned + external).associateBy(BytecodeClass::internalName)
        return BytecodeInventory(adjustedOwned.associateBy(BytecodeClass::internalName), hierarchy)
    }

    private fun type(
        name: String,
        superName: String? = "java/lang/Object",
        interfaces: List<String> = emptyList(),
        access: Int = Opcodes.ACC_PUBLIC,
        methods: List<BytecodeMethod> = emptyList(),
    ) = BytecodeClass(name, ":app", "$name.java", null, access, superName, interfaces, emptySet(), emptyList(), methods)

    private fun objectType() = type("java/lang/Object", superName = null)

    private fun method(owner: String, name: String, descriptor: String, access: Int = Opcodes.ACC_PUBLIC) =
        BytecodeMethod(owner, name, descriptor, access, emptySet())
}
