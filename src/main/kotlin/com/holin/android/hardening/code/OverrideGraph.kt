package com.holin.android.hardening.code

import java.util.ArrayDeque
import java.util.Collections
import java.util.LinkedHashSet
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type

class OverrideGroup(id: String, members: Collection<CodeSymbolKey>, touchesExternal: Boolean) {
    val id: String = id
    val members: Set<CodeSymbolKey> = Collections.unmodifiableSet(LinkedHashSet(members))
    val touchesExternal: Boolean = touchesExternal

    override fun equals(other: Any?): Boolean = other is OverrideGroup &&
        id == other.id && members == other.members && touchesExternal == other.touchesExternal

    override fun hashCode(): Int = 31 * (31 * id.hashCode() + members.hashCode()) + touchesExternal.hashCode()
    override fun toString(): String = "OverrideGroup(id=$id, members=$members, touchesExternal=$touchesExternal)"
}

class OverrideGraphBuilder {
    fun build(inventory: BytecodeInventory): List<OverrideGroup> {
        val declarations = inventory.hierarchyClasses.values
            .sortedBy(BytecodeClass::internalName)
            .flatMap { owner -> owner.methods.mapNotNull { method -> virtualDeclaration(owner, method) } }
        val byOwner = declarations.groupBy { it.owner.internalName }
        val edges = declarations.associate { it.key to linkedSetOf<CodeSymbolKey>() }.toMutableMap()

        declarations.forEach { declaration ->
            ancestors(declaration.owner, inventory).forEach { ancestor ->
                byOwner[ancestor.internalName].orEmpty()
                    .filter { parent -> overrides(declaration, parent, inventory) }
                    .forEach { parent -> connect(edges, declaration.key, parent.key) }
            }
        }
        connectInheritedDispatch(inventory, byOwner, edges)
        byOwner.values.forEach { siblings ->
            // Task 1 intentionally stores headers only. Joining every compatible target can over-group an
            // ambiguous overload set, but it cannot miss the actual delegate of an external bridge contract.
            siblings.filter { it.method.access has Opcodes.ACC_BRIDGE }.forEach { bridge ->
                siblings.filter { target -> target !== bridge && !(target.method.access has Opcodes.ACC_BRIDGE) }
                    .filter { target -> bridgeTargetCompatible(bridge, target, inventory) }
                    .forEach { target -> connect(edges, bridge.key, target.key) }
            }
        }

        val groups = connectedComponents(edges).map { members ->
            OverrideGroup(
                id = members.minOf(CodeSymbolKey::canonicalIdentity),
                members = members,
                touchesExternal = members.any { it.owner !in inventory.ownedClasses },
            )
        }.sortedBy(OverrideGroup::id)
        return Collections.unmodifiableList(ArrayList(groups))
    }

    private fun connectInheritedDispatch(
        inventory: BytecodeInventory,
        byOwner: Map<String, List<Declaration>>,
        edges: MutableMap<CodeSymbolKey, LinkedHashSet<CodeSymbolKey>>,
    ) {
        inventory.hierarchyClasses.values.sortedBy(BytecodeClass::internalName).forEach { dispatchType ->
            val interfaces = interfaceAncestry(dispatchType, inventory)
            interfaces.flatMap { byOwner[it.internalName].orEmpty() }.forEach { contract ->
                val inherited = effectiveClassImplementations(dispatchType, contract, byOwner, inventory)
                val implementations = inherited.ifEmpty { effectiveDefaults(interfaces, contract, byOwner, inventory) }
                implementations.filter { it.key != contract.key }.forEach { implementation ->
                    connect(edges, implementation.key, contract.key)
                }
            }
        }
    }

    private fun effectiveClassImplementations(
        dispatchType: BytecodeClass,
        contract: Declaration,
        byOwner: Map<String, List<Declaration>>,
        inventory: BytecodeInventory,
    ): List<Declaration> {
        if (dispatchType.access has Opcodes.ACC_INTERFACE) return emptyList()
        val seen = mutableSetOf<String>()
        var current: BytecodeClass? = dispatchType
        while (current != null && seen.add(current.internalName)) {
            val matches = byOwner[current.internalName].orEmpty().filter { candidate ->
                overrides(candidate, contract, inventory)
            }
            if (matches.isNotEmpty()) return matches
            current = current.superName?.let(inventory.hierarchyClasses::get)
        }
        return emptyList()
    }

    private fun effectiveDefaults(
        interfaces: List<BytecodeClass>,
        contract: Declaration,
        byOwner: Map<String, List<Declaration>>,
        inventory: BytecodeInventory,
    ): List<Declaration> {
        val candidates = interfaces.flatMap { byOwner[it.internalName].orEmpty() }
            .filter { candidate -> !(candidate.method.access has Opcodes.ACC_ABSTRACT) }
            .filter { candidate -> overrides(candidate, contract, inventory) }
        return candidates.filter { candidate ->
            candidates.none { other ->
                other.owner.internalName != candidate.owner.internalName &&
                    isSubtype(other.owner.internalName, candidate.owner.internalName, inventory)
            }
        }
    }

    private fun interfaceAncestry(owner: BytecodeClass, inventory: BytecodeInventory): List<BytecodeClass> {
        val roots = mutableListOf<String>()
        val classSeen = mutableSetOf<String>()
        var current: BytecodeClass? = owner
        while (current != null && classSeen.add(current.internalName)) {
            if (current.access has Opcodes.ACC_INTERFACE) roots += current.internalName
            roots += current.interfaces
            current = if (current.access has Opcodes.ACC_INTERFACE) null else {
                current.superName?.let(inventory.hierarchyClasses::get)
            }
        }

        val result = mutableListOf<BytecodeClass>()
        val seen = mutableSetOf<String>()
        val pending = ArrayDeque<String>().apply { roots.forEach(::addLast) }
        while (pending.isNotEmpty()) {
            val name = pending.removeFirst()
            if (!seen.add(name)) continue
            val value = inventory.hierarchyClasses[name] ?: continue
            result += value
            value.interfaces.forEach(pending::addLast)
        }
        return result
    }

    private fun virtualDeclaration(owner: BytecodeClass, method: BytecodeMethod): Declaration? {
        if (method.name == "<init>" || method.name == "<clinit>") return null
        if (method.access has Opcodes.ACC_PRIVATE || method.access has Opcodes.ACC_STATIC) return null
        return Declaration(owner, method, methodKey(method))
    }

    private fun overrides(child: Declaration, parent: Declaration, inventory: BytecodeInventory): Boolean {
        if (child.method.name != parent.method.name) return false
        if (parent.method.access has Opcodes.ACC_FINAL) return false
        if (!visibleFrom(parent, child.owner)) return false
        if (!visibilityCompatible(child.method.access, parent.method.access)) return false
        val childType = Type.getMethodType(child.method.descriptor)
        val parentType = Type.getMethodType(parent.method.descriptor)
        return childType.argumentTypes.contentEquals(parentType.argumentTypes) &&
            returnCompatible(childType.returnType, parentType.returnType, inventory)
    }

    private fun bridgeTargetCompatible(bridge: Declaration, target: Declaration, inventory: BytecodeInventory): Boolean {
        if (bridge.method.name != target.method.name) return false
        val bridgeType = Type.getMethodType(bridge.method.descriptor)
        val targetType = Type.getMethodType(target.method.descriptor)
        if (bridgeType.argumentTypes.size != targetType.argumentTypes.size) return false
        if (!targetType.argumentTypes.zip(bridgeType.argumentTypes).all { (targetArgument, bridgeArgument) ->
                returnCompatible(targetArgument, bridgeArgument, inventory)
            }
        ) return false
        return returnCompatible(targetType.returnType, bridgeType.returnType, inventory)
    }

    private fun visibleFrom(parent: Declaration, childOwner: BytecodeClass): Boolean {
        val access = parent.method.access
        if (access has Opcodes.ACC_PRIVATE || access has Opcodes.ACC_STATIC) return false
        if (access has Opcodes.ACC_PUBLIC || access has Opcodes.ACC_PROTECTED) return true
        return packageName(parent.owner.internalName) == packageName(childOwner.internalName)
    }

    private fun visibilityCompatible(child: Int, parent: Int): Boolean = when {
        parent has Opcodes.ACC_PUBLIC -> child has Opcodes.ACC_PUBLIC
        parent has Opcodes.ACC_PROTECTED -> child has Opcodes.ACC_PUBLIC || child has Opcodes.ACC_PROTECTED
        else -> true
    }

    private fun returnCompatible(child: Type, parent: Type, inventory: BytecodeInventory): Boolean {
        if (child == parent) return true
        if (parent.sort == Type.OBJECT) {
            if (child.sort == Type.ARRAY) return parent.internalName in ARRAY_SUPERTYPES
            return child.sort == Type.OBJECT && isSubtype(child.internalName, parent.internalName, inventory)
        }
        if (parent.sort != Type.ARRAY || child.sort != Type.ARRAY) return false
        return returnCompatible(arrayComponent(child), arrayComponent(parent), inventory)
    }

    private fun arrayComponent(type: Type): Type = Type.getType(type.descriptor.substring(1))

    private fun isSubtype(child: String, parent: String, inventory: BytecodeInventory): Boolean {
        if (child == parent || parent == "java/lang/Object") return true
        val seen = mutableSetOf<String>()
        val pending = ArrayDeque<String>().apply { add(child) }
        while (pending.isNotEmpty()) {
            val name = pending.removeFirst()
            if (!seen.add(name)) continue
            val value = inventory.hierarchyClasses[name] ?: continue
            val direct = listOfNotNull(value.superName) + value.interfaces
            if (parent in direct) return true
            direct.forEach(pending::addLast)
        }
        return false
    }

    private fun ancestors(owner: BytecodeClass, inventory: BytecodeInventory): List<BytecodeClass> {
        val result = mutableListOf<BytecodeClass>()
        val seen = mutableSetOf<String>()
        val pending = ArrayDeque<String>()
        listOfNotNull(owner.superName).plus(owner.interfaces).forEach(pending::addLast)
        while (pending.isNotEmpty()) {
            val name = pending.removeFirst()
            if (!seen.add(name)) continue
            val value = inventory.hierarchyClasses[name] ?: continue
            result += value
            listOfNotNull(value.superName).plus(value.interfaces).forEach(pending::addLast)
        }
        return result
    }

    private fun connect(
        edges: MutableMap<CodeSymbolKey, LinkedHashSet<CodeSymbolKey>>,
        left: CodeSymbolKey,
        right: CodeSymbolKey,
    ) {
        edges.getValue(left) += right
        edges.getValue(right) += left
    }

    private fun connectedComponents(edges: Map<CodeSymbolKey, Set<CodeSymbolKey>>): List<Set<CodeSymbolKey>> {
        val visited = mutableSetOf<CodeSymbolKey>()
        return edges.keys.sortedBy(CodeSymbolKey::canonicalIdentity).mapNotNull { root ->
            if (!visited.add(root)) return@mapNotNull null
            val members = sortedSetOf(compareBy(CodeSymbolKey::canonicalIdentity))
            val pending = ArrayDeque<CodeSymbolKey>().apply { add(root) }
            while (pending.isNotEmpty()) {
                val current = pending.removeFirst()
                members += current
                edges.getValue(current).sortedBy(CodeSymbolKey::canonicalIdentity).forEach { next ->
                    if (visited.add(next)) pending.addLast(next)
                }
            }
            members
        }
    }

    private data class Declaration(
        val owner: BytecodeClass,
        val method: BytecodeMethod,
        val key: CodeSymbolKey,
    )

    private infix fun Int.has(flag: Int): Boolean = this and flag != 0
    private fun packageName(name: String): String = name.substringBeforeLast('/', "")

    private companion object {
        val ARRAY_SUPERTYPES = setOf("java/lang/Object", "java/lang/Cloneable", "java/io/Serializable")
    }
}

internal fun methodKey(method: BytecodeMethod) = CodeSymbolKey(
    kind = CodeSymbolKind.METHOD,
    owner = method.owner,
    name = method.name,
    descriptor = method.descriptor,
)
