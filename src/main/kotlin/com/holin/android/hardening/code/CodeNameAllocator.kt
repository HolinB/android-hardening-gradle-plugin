package com.holin.android.hardening.code

import com.holin.android.hardening.naming.AliasNamespace
import com.holin.android.hardening.naming.AliasRequest
import com.holin.android.hardening.naming.PseudowordRegistry
import com.holin.android.hardening.naming.RegistryAssignment
import com.holin.android.hardening.naming.RegistryKey
import com.holin.android.hardening.naming.RegistrySnapshot
import com.holin.android.hardening.naming.SymbolKind
import java.util.ArrayList
import java.util.Collections
import java.util.LinkedHashSet
import java.util.Locale

data class AssignedCodeName(val key: CodeSymbolKey, val alias: String, val outputOwner: String)

sealed class CodeNamePlan protected constructor() {
    abstract val assignments: List<AssignedCodeName>
    abstract val exclusions: List<CodeExclusion>
    abstract val registry: RegistrySnapshot
    abstract val ownedOriginalOwners: Set<String>
}

private class ImmutableCodeNamePlan(
    assignments: Collection<AssignedCodeName>,
    exclusions: Collection<CodeExclusion>,
    registry: RegistrySnapshot,
    ownedOriginalOwners: Collection<String>,
) : CodeNamePlan() {
    override val assignments: List<AssignedCodeName> = immutableList(assignments.sortedBy { it.key.canonicalIdentity })
    override val exclusions: List<CodeExclusion> = immutableList(exclusions.sortedWith(EXCLUSION_ORDER))
    override val registry: RegistrySnapshot = registry.copy(
        assignments = immutableList(registry.assignments.sortedBy(RegistryAssignment::keyHash)),
        tombstones = immutableList(registry.tombstones.sortedWith(compareBy({ it.keyHash }, { it.retiredGeneration }))),
    )
    override val ownedOriginalOwners: Set<String> = Collections.unmodifiableSet(LinkedHashSet(ownedOriginalOwners.sorted()))

    override fun equals(other: Any?): Boolean = other is CodeNamePlan &&
        assignments == other.assignments && exclusions == other.exclusions && registry == other.registry &&
        ownedOriginalOwners == other.ownedOriginalOwners

    override fun hashCode(): Int = 31 * (31 * (31 * assignments.hashCode() + exclusions.hashCode()) + registry.hashCode()) +
        ownedOriginalOwners.hashCode()
    override fun toString(): String = "ImmutableCodeNamePlan(assignments=$assignments, exclusions=$exclusions, registry=$registry, " +
        "ownedOriginalOwners=$ownedOriginalOwners)"
}

class CodeNameAllocator(private val registry: PseudowordRegistry) {
    fun allocate(
        inventory: CodeNamingInventory,
        bytecode: BytecodeInventory,
        generation: Long,
    ): CodeNamePlan {
        require(generation > 0) { "generation must be positive" }
        val eligible = validateInventory(inventory, bytecode)
        val eligibleClasses = eligible.filter { it.key.kind == CodeSymbolKind.CLASS }
        val preservedPackages = inventory.exclusions.asSequence()
            .filter { it.key.kind == CodeSymbolKind.CLASS }
            .map { it.key.owner.substringBeforeLast('/', "") }
            .toSet()
        val packageOutputs = allocatePackages(eligibleClasses, bytecode, preservedPackages, generation)
        val classAssignments = allocateClasses(eligibleClasses, bytecode, packageOutputs, generation)
        val classOutputs = classAssignments.associate { it.key.owner to it.outputOwner }
        val memberAssignments = allocateMembers(
            eligible.filter { it.key.kind != CodeSymbolKind.CLASS },
            bytecode,
            classOutputs,
            generation,
        )
        return ImmutableCodeNamePlan(
            classAssignments + memberAssignments,
            inventory.exclusions,
            registry.snapshot(generation),
            bytecode.ownedClasses.values.filter { it.modulePath != null }
                .map(BytecodeClass::internalName),
        )
    }

    private fun validateInventory(
        inventory: CodeNamingInventory,
        bytecode: BytecodeInventory,
    ): List<EligibleCodeSymbol> {
        val overrideGroups = OverrideGraphBuilder().build(bytecode).flatMap { group ->
            group.members.map { key -> key to group }
        }.toMap()
        val eligibleByKey = linkedMapOf<CodeSymbolKey, EligibleCodeSymbol>()
        inventory.eligible.forEach { symbol ->
            val prior = eligibleByKey.putIfAbsent(symbol.key, symbol)
            require(prior == null || prior == symbol) { "eligible code symbol has inconsistent override groups: ${symbol.key}" }
            require(symbol.key.owner in bytecode.ownedClasses) {
                "eligible code symbol is not owned bytecode: ${symbol.key.canonicalIdentity}"
            }
            val owner = bytecode.ownedClasses.getValue(symbol.key.owner)
            require(owner.modulePath != null) { "eligible code symbol has no owning module: ${symbol.key.canonicalIdentity}" }
            when (symbol.key.kind) {
                CodeSymbolKind.CLASS -> {
                    require(symbol.key == classKey(owner)) { "eligible class key does not match owned bytecode: ${symbol.key}" }
                    require(symbol.overrideGroupId == null) { "class symbol cannot have an override group" }
                }
                CodeSymbolKind.FIELD -> {
                    require(owner.fields.any { fieldKey(it) == symbol.key }) {
                        "eligible field key does not match owned bytecode: ${symbol.key}"
                    }
                    require(symbol.overrideGroupId == null) { "field symbol cannot have an override group" }
                }
                CodeSymbolKind.METHOD -> {
                    require(symbol.key.name !in SPECIAL_METHODS) { "constructors cannot receive code aliases: ${symbol.key}" }
                    require(owner.methods.any { methodKey(it) == symbol.key }) {
                        "eligible method key does not match owned bytecode: ${symbol.key}"
                    }
                    val overrideGroup = overrideGroups[symbol.key]
                    require(overrideGroup == null || !overrideGroup.touchesExternal) {
                        "eligible method belongs to an external override family: ${symbol.key}"
                    }
                    require(symbol.overrideGroupId == overrideGroup?.id) {
                        "eligible method override group does not match bytecode: ${symbol.key}"
                    }
                }
            }
        }
        val excluded = inventory.exclusions.mapTo(hashSetOf(), CodeExclusion::key)
        require(eligibleByKey.keys.none { it in excluded }) { "code symbol cannot be both eligible and excluded" }
        inventory.exclusions.forEach { exclusion ->
            require(exclusion.key.owner in bytecode.hierarchyClasses) {
                "code exclusion is outside bytecode inventory: ${exclusion.key.canonicalIdentity}"
            }
        }
        return eligibleByKey.values.sortedWith(compareBy({ it.key.canonicalIdentity }, { it.key.kind.name }))
    }

    private fun allocatePackages(
        eligibleClasses: List<EligibleCodeSymbol>,
        bytecode: BytecodeInventory,
        preservedPackages: Set<String>,
        generation: Long,
    ): Map<String, String> {
        val packages = eligibleClasses.mapTo(sortedSetOf()) { it.key.owner.substringBeforeLast('/', "") }
        val prefixes = packages.asSequence()
            .filterNot(preservedPackages::contains)
            .flatMap { packageName -> packagePrefixes(packageName).asSequence() }
            .toCollection(sortedSetOf())
        if (prefixes.isEmpty()) {
            registry.reconcileScoped(emptyList(), generation, setOf(SymbolKind.PACKAGE))
            return packages.associateWith { packageName -> if (packageName in preservedPackages) packageName else "" }
        }

        val requests = prefixes.map(::packageRequest)
        val reservedSegments = bytecode.hierarchyClasses.keys.asSequence()
            .map { it.substringAfterLast('/') }
            .mapNotNull { reservationAlias(SymbolKind.PACKAGE, it) }
            .toSortedSet()
        val reservations = requests.mapTo(linkedSetOf()) { AliasNamespace(it.namespace, SymbolKind.PACKAGE) }
            .associateWith { reservedSegments }
        val aliases = registry.reconcileScoped(
            requests = requests,
            generation = generation,
            kinds = setOf(SymbolKind.PACKAGE),
            reservedAliases = reservations,
        )
        val outputByPrefix = linkedMapOf<String, String>()
        prefixes.sortedWith(compareBy({ it.count { character -> character == '/' } }, { it })).forEach { prefix ->
            val parent = prefix.substringBeforeLast('/', "")
            outputByPrefix[prefix] = joinInternalName(
                if (parent.isEmpty()) "" else outputByPrefix.getValue(parent),
                aliases.getValue(packageRequest(prefix).key),
            )
        }
        val hierarchyNames = bytecode.hierarchyClasses.keys.mapTo(hashSetOf(), ::caseFold)
        outputByPrefix.values.forEach { outputPackage ->
            require(caseFold(outputPackage) !in hierarchyNames) {
                "allocated package collides with a classpath descriptor: $outputPackage"
            }
        }
        return packages.associateWith { packageName ->
            when {
                packageName in preservedPackages -> packageName
                packageName.isEmpty() -> ""
                else -> outputByPrefix.getValue(packageName)
            }
        }
    }

    private fun allocateClasses(
        eligibleClasses: List<EligibleCodeSymbol>,
        bytecode: BytecodeInventory,
        packageOutputs: Map<String, String>,
        generation: Long,
    ): List<AssignedCodeName> {
        val plannedPackages = packageOutputs.values.flatMapTo(sortedSetOf()) { output -> packagePrefixes(output) }
        val requests = eligibleClasses.map { symbol ->
            val originalPackage = symbol.key.owner.substringBeforeLast('/', "")
            val outputPackage = packageOutputs.getValue(originalPackage)
            AliasRequest(classRegistryKey(symbol.key), classNamespace(outputPackage))
        }
        val reservations = requests.mapTo(linkedSetOf()) { AliasNamespace(it.namespace, SymbolKind.CLASS) }
            .associateWith { scope ->
                val outputPackage = outputPackage(scope.namespace)
                buildSet {
                    addAll(visibleClassNames(bytecode, outputPackage))
                    plannedPackages.asSequence()
                        .filter { it.substringBeforeLast('/', "") == outputPackage }
                        .map { it.substringAfterLast('/') }
                        .mapNotNull { reservationAlias(SymbolKind.CLASS, it) }
                        .forEach(::add)
                }
            }
        val aliases = registry.reconcileScoped(
            requests = requests,
            generation = generation,
            kinds = setOf(SymbolKind.CLASS),
            reservedAliases = reservations,
        )
        return eligibleClasses.map { symbol ->
            val outputPackage = packageOutputs.getValue(symbol.key.owner.substringBeforeLast('/', ""))
            val alias = aliases.getValue(classRegistryKey(symbol.key))
            AssignedCodeName(symbol.key, alias, joinInternalName(outputPackage, alias))
        }.also { assignments ->
            val outputs = assignments.map(AssignedCodeName::outputOwner)
            require(outputs.distinctBy(::caseFold).size == outputs.size) {
                "allocated classes have duplicate output descriptors"
            }
            val hierarchyNames = bytecode.hierarchyClasses.keys.mapTo(hashSetOf(), ::caseFold)
            val packageNames = plannedPackages.mapTo(hashSetOf(), ::caseFold)
            outputs.forEach { output ->
                require(caseFold(output) !in hierarchyNames) {
                    "allocated class collides with a classpath descriptor: $output"
                }
                require(caseFold(output) !in packageNames) {
                    "allocated class collides with a planned package: $output"
                }
            }
        }
    }

    private fun allocateMembers(
        eligibleMembers: List<EligibleCodeSymbol>,
        bytecode: BytecodeInventory,
        classOutputs: Map<String, String>,
        generation: Long,
    ): List<AssignedCodeName> {
        val groups = eligibleMembers.groupBy { symbol -> memberGroupIdentity(symbol) }
            .toSortedMap()
        val predecessors = persistedGroupPredecessors(groups)
        val requests = groups.map { (identity, members) ->
            val kind = members.singleOrNull()?.key?.kind
            val descriptor = if (kind == CodeSymbolKind.FIELD) {
                members.single().key.descriptor
            } else {
                METHOD_GROUP_DESCRIPTOR_PREFIX + members.map { it.key.canonicalIdentity }.sorted().joinToString("\n")
            }
            AliasRequest(
                key = RegistryKey(identity, SymbolKind.MEMBER, descriptor),
                namespace = MEMBER_NAMESPACE,
                predecessorKeys = predecessors[identity].orEmpty(),
            )
        }
        val visibleMembers = bytecode.hierarchyClasses.values.asSequence()
            .flatMap { owner -> owner.fields.asSequence().map(BytecodeField::name) + owner.methods.asSequence().map(BytecodeMethod::name) }
            .mapNotNull { reservationAlias(SymbolKind.MEMBER, it) }
            .toSortedSet()
        val aliases = registry.reconcileScoped(
            requests = requests,
            generation = generation,
            kinds = setOf(SymbolKind.MEMBER),
            reservedAliases = mapOf(AliasNamespace(MEMBER_NAMESPACE, SymbolKind.MEMBER) to visibleMembers),
        )
        return groups.flatMap { (identity, members) ->
            val request = requests.single { it.key.originalIdentity == identity }
            val alias = aliases.getValue(request.key)
            members.map { symbol ->
                AssignedCodeName(symbol.key, alias, classOutputs[symbol.key.owner] ?: symbol.key.owner)
            }
        }
    }

    private fun persistedGroupPredecessors(
        groups: Map<String, List<EligibleCodeSymbol>>,
    ): Map<String, Set<RegistryKey>> {
        val persisted = registry.snapshot(generation = 1).assignments.filter { assignment ->
            assignment.key.kind == SymbolKind.MEMBER && assignment.namespace == MEMBER_NAMESPACE
        }
        return groups.filterValues { members -> members.first().key.kind == CodeSymbolKind.METHOD }.mapValues { (_, members) ->
            val identities = members.mapTo(hashSetOf()) { it.key.canonicalIdentity }
            val currentGroup = members.first().overrideGroupId
            val prior = persisted.filter { assignment ->
                assignment.key.originalIdentity.startsWith(METHOD_GROUP_PREFIX) &&
                    (
                        persistedGroupMembers(assignment).any(identities::contains) ||
                            assignment.key.originalIdentity.removePrefix(METHOD_GROUP_PREFIX) == currentGroup
                    )
            }
            require(prior.map(RegistryAssignment::alias).distinct().size <= 1) {
                "persisted override groups merge with different aliases: " + prior.joinToString { it.key.originalIdentity }
            }
            prior.mapTo(linkedSetOf()) { it.key }
        }
    }

    private fun persistedGroupMembers(assignment: RegistryAssignment): Set<String> =
        if (assignment.key.descriptor.startsWith(METHOD_GROUP_DESCRIPTOR_PREFIX)) {
            assignment.key.descriptor.removePrefix(METHOD_GROUP_DESCRIPTOR_PREFIX)
                .split('\n')
                .filterTo(linkedSetOf(), String::isNotEmpty)
        } else {
            setOf(assignment.key.originalIdentity.removePrefix(METHOD_GROUP_PREFIX))
        }

    private fun memberGroupIdentity(symbol: EligibleCodeSymbol): String = when (symbol.key.kind) {
        CodeSymbolKind.FIELD -> fieldRegistryIdentity(symbol.key)
        CodeSymbolKind.METHOD -> "$METHOD_GROUP_PREFIX${symbol.overrideGroupId ?: symbol.key.canonicalIdentity}"
        CodeSymbolKind.CLASS -> error("class cannot be allocated in the member pass")
    }

    private fun packageRequest(prefix: String): AliasRequest = AliasRequest(
        RegistryKey(prefix, SymbolKind.PACKAGE, PACKAGE_SEGMENT_DESCRIPTOR),
        packageNamespace(prefix.substringBeforeLast('/', "")),
    )

    private fun packageNamespace(originalParent: String): String = "$PACKAGE_NAMESPACE_PREFIX$originalParent"
    private fun classRegistryKey(key: CodeSymbolKey) = RegistryKey(key.canonicalIdentity, SymbolKind.CLASS, key.descriptor)
    private fun classNamespace(outputPackage: String) = if (outputPackage.isEmpty()) ROOT_CLASS_NAMESPACE else outputPackage
    private fun outputPackage(classNamespace: String) = if (classNamespace == ROOT_CLASS_NAMESPACE) "" else classNamespace

    private fun packagePrefixes(packageName: String): List<String> {
        if (packageName.isEmpty()) return emptyList()
        val segments = packageName.split('/')
        return segments.indices.map { index -> segments.take(index + 1).joinToString("/") }
    }

    private fun visibleClassNames(bytecode: BytecodeInventory, outputParent: String): Set<String> =
        bytecode.hierarchyClasses.keys.asSequence()
        .filter { caseFold(it.substringBeforeLast('/', "")) == caseFold(outputParent) }
        .map { it.substringAfterLast('/') }
        .mapNotNull { reservationAlias(SymbolKind.CLASS, it) }
        .toSortedSet()

    private fun reservationAlias(kind: SymbolKind, visibleName: String): String? {
        val folded = caseFold(visibleName)
        if (!PACKAGE_ALIAS.matches(folded)) return null
        return when (kind) {
            SymbolKind.CLASS -> folded.replaceFirstChar(Char::uppercaseChar)
            SymbolKind.MEMBER,
            SymbolKind.PACKAGE,
            -> folded
            SymbolKind.RESOURCE -> error("resource aliases are outside code allocation")
        }
    }

    private fun caseFold(value: String): String = value.lowercase(Locale.ROOT)

    private fun joinInternalName(parent: String, child: String): String = if (parent.isEmpty()) child else "$parent/$child"

    private companion object {
        const val PACKAGE_NAMESPACE_PREFIX = "code-package-segments-v1:"
        const val ROOT_CLASS_NAMESPACE = "code-classes-root-v1"
        const val MEMBER_NAMESPACE = "code-members-v2"
        const val PACKAGE_SEGMENT_DESCRIPTOR = "package-segment"
        const val METHOD_GROUP_DESCRIPTOR_PREFIX = "method-group-v2\n"
        const val METHOD_GROUP_PREFIX = "override:"
        val PACKAGE_ALIAS = Regex("[a-z][a-z0-9]*")
        val SPECIAL_METHODS = setOf("<init>", "<clinit>")
    }
}

internal fun fieldRegistryIdentity(key: CodeSymbolKey): String {
    require(key.kind == CodeSymbolKind.FIELD) { "field registry identity requires a field symbol" }
    return "field:${key.canonicalIdentity}"
}

private val EXCLUSION_ORDER = compareBy<CodeExclusion>(
    { it.key.canonicalIdentity },
    { it.key.kind.name },
    { it.reason.ordinal },
    CodeExclusion::evidence,
)

private fun <T> immutableList(values: Collection<T>): List<T> = Collections.unmodifiableList(ArrayList(values))
