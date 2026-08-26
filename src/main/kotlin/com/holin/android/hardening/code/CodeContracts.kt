package com.holin.android.hardening.code

import com.holin.android.hardening.HardcodedReferenceKind
import com.holin.android.hardening.audit.ExternalNameCandidate
import com.holin.android.hardening.audit.ExternalNameContractKind
import com.holin.android.hardening.audit.HardeningSourceAudit
import com.holin.android.hardening.audit.UnresolvedContractKind
import java.nio.file.Path
import java.util.ArrayList
import java.util.Collections
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type

enum class CodeSymbolKind { CLASS, FIELD, METHOD }

data class CodeSymbolKey(
    val kind: CodeSymbolKind,
    val owner: String,
    val name: String,
    val descriptor: String,
) {
    val canonicalIdentity: String = "$owner#$name$descriptor"
}

// Declaration order is the stable report precedence when one symbol has multiple preservation contracts.
enum class CodeExclusionReason {
    CONSTRUCTOR,
    UNPROVEN_SOURCE,
    EXTERNAL_OVERRIDE,
    SYNTHETIC_BRIDGE_EXTERNAL,
    GSON_UNEXPLICIT_FIELD,
    SERIALIZABLE,
    OBJECTBOX_ENTITY,
    JAVASCRIPT_INTERFACE,
    JNI_NATIVE,
    EXPORTED_COMPONENT,
    MANIFEST_DECLARED_CLASS,
    LAYOUT_CUSTOM_VIEW,
    GENERATED_VIEW_BINDING_REFLECTION,
    PLATFORM_REFLECTION,
    ANDROID_VIEW_PROPERTY,
    EVENTBUS_SUBSCRIBER,
    GENERATED_ENUM_API,
    CALLBACK_PARAMETER_KEEP_RULE,
    ACTIVITY_VIEW_CALLBACK_KEEP_RULE,
    GOROUTER_PARAM_FIELD_KEEP_RULE,
    GOROUTER_COMPONENT_KEEP_RULE,
    RECYCLERVIEW_LAYOUT_MANAGER_KEEP_RULE,
    COORDINATOR_LAYOUT_BEHAVIOR_KEEP_RULE,
    ANDROID_STARTUP_KEEP_RULE,
    POTENTIAL_BEAN_INSTANCE_FIELD,
    HARDCODED_MEMBER_NAME,
    R8_HIERARCHY_KEEP_RULE,
}

data class CodeExclusion(val key: CodeSymbolKey, val reason: CodeExclusionReason, val evidence: String)
data class EligibleCodeSymbol(val key: CodeSymbolKey, val overrideGroupId: String?)
class CodeNamingInventory(eligible: Collection<EligibleCodeSymbol>, exclusions: Collection<CodeExclusion>) {
    val eligible: List<EligibleCodeSymbol> = Collections.unmodifiableList(ArrayList(eligible))
    val exclusions: List<CodeExclusion> = Collections.unmodifiableList(ArrayList(exclusions))

    override fun equals(other: Any?): Boolean = other is CodeNamingInventory &&
        eligible == other.eligible && exclusions == other.exclusions

    override fun hashCode(): Int = 31 * eligible.hashCode() + exclusions.hashCode()
    override fun toString(): String = "CodeNamingInventory(eligible=$eligible, exclusions=$exclusions)"
}

class OwnedCodeContractClassifier {
    private val exactClassNameReasons = setOf(
        CodeExclusionReason.MANIFEST_DECLARED_CLASS,
        CodeExclusionReason.LAYOUT_CUSTOM_VIEW,
    )

    fun classify(
        bytecode: BytecodeInventory,
        sourceAudit: HardeningSourceAudit,
        potentialBeanFields: Collection<PotentialBeanField> = PotentialBeanFieldPolicy().inventory(bytecode),
        effectiveR8Rules: String = "",
    ): CodeNamingInventory {
        val unresolved = sourceAudit.unresolvedContracts.filter {
            it.kind == UnresolvedContractKind.APP_REFLECTION ||
                it.kind == UnresolvedContractKind.GSON_FIELD_NAMING_STRATEGY
        }
        require(unresolved.isEmpty()) {
            "unresolved code contract prevents stable naming: " +
                unresolved.joinToString { "${it.sourceFile}:${it.line} (${it.reason})" }
        }

        val groups = OverrideGraphBuilder().build(bytecode)
        val exclusions = mutableListOf<CodeExclusion>()
        exclusions += unresolvedOwnedBytecode(bytecode)
        groups.filter(OverrideGroup::touchesExternal).forEach { group ->
            group.members.filter { it.owner in bytecode.ownedClasses }.forEach { key ->
                val owner = bytecode.ownedClasses.getValue(key.owner)
                val method = owner.methods.single { methodKey(it) == key }
                val reason = if (method.access and Opcodes.ACC_BRIDGE != 0) {
                    CodeExclusionReason.SYNTHETIC_BRIDGE_EXTERNAL
                } else {
                    CodeExclusionReason.EXTERNAL_OVERRIDE
                }
                exclusions += CodeExclusion(key, reason, "override group ${group.id} touches a non-owned declaration")
            }
        }
        bytecode.ownedClasses.values.forEach { owner ->
            owner.methods.filter { it.name == "<init>" || it.name == "<clinit>" }.forEach { method ->
                exclusions += CodeExclusion(methodKey(method), CodeExclusionReason.CONSTRUCTOR, "JVM constructor or class initializer")
            }
        }
        exclusions += generatedEnumApiMethods(bytecode)
        exclusions += callbackParameterKeepRuleMethods(bytecode)
        exclusions += activityViewCallbackKeepRuleMethods(bytecode)
        exclusions += eventBusSubscriberMethods(bytecode)
        exclusions += androidViewPropertyMethods(bytecode)
        exclusions += externalKeepContractExclusions(bytecode)
        exclusions += R8HierarchyKeepContractAnalyzer().exclusions(bytecode, effectiveR8Rules)
        sourceAudit.externalNameCandidates.forEach { candidate ->
            exclusions += resolveExternalCandidate(bytecode, candidate)
        }
        exclusions += hardcodedMemberExclusions(bytecode, sourceAudit)
        exclusions += PotentialBeanFieldPolicy().exclusions(potentialBeanFields)

        val canonicalExclusions = canonicalizeExactClassExclusions(exclusions)
        val excludedKeys = canonicalExclusions.mapTo(hashSetOf(), CodeExclusion::key)
        val internalGroups = groups.filterNot(OverrideGroup::touchesExternal)
            .flatMap { group -> group.members.map { it to group.id } }
            .toMap()
        val eligible = bytecode.ownedClasses.values.flatMap(::symbols)
            .filterNot { it in excludedKeys }
            .map { key -> EligibleCodeSymbol(key, if (key.kind == CodeSymbolKind.METHOD) internalGroups[key] else null) }
            .sortedWith(compareBy({ it.key.canonicalIdentity }, { it.key.kind.name }))
        return CodeNamingInventory(
            eligible = eligible,
            exclusions = canonicalExclusions.distinct().sortedWith(
                compareBy({ it.key.canonicalIdentity }, { it.key.kind.name }, { it.reason.ordinal }, CodeExclusion::evidence),
            ),
        )
    }

    private fun hardcodedMemberExclusions(
        bytecode: BytecodeInventory,
        sourceAudit: HardeningSourceAudit,
    ): List<CodeExclusion> = sourceAudit.hardcodedReferenceFindings
        .filter { it.kind == HardcodedReferenceKind.MEMBER_NAME }
        .mapNotNull { finding ->
            val ownerName = requireNotNull(finding.ownerInternalName) {
                "hardcoded member reference has no exact original owner: ${finding.sourceFile}:${finding.line}"
            }
            val owner = bytecode.ownedClasses[ownerName] ?: return@mapNotNull null
            val memberName = finding.value.substringBefore('(')
            val matches = if (finding.jvmDescriptor == null) {
                owner.fields.filter { it.name == memberName }.map(::fieldKey)
            } else {
                owner.methods.filter { method ->
                    method.name == memberName && method.descriptor.substringBefore(')') + ")" == finding.jvmDescriptor
                }.map(::methodKey)
            }
            require(matches.isNotEmpty()) {
                "hardcoded member resolved to zero owned symbols: ${finding.sourceFile}:${finding.line} ${finding.value}"
            }
            require(matches.size == 1) {
                "hardcoded member resolved to multiple owned symbols: ${finding.sourceFile}:${finding.line} ${finding.value}"
            }
            CodeExclusion(
                matches.single(),
                CodeExclusionReason.HARDCODED_MEMBER_NAME,
                "MEMBER_NAME at ${finding.sourceFile}:${finding.line}: $ownerName#${finding.value}",
            )
        }

    private fun canonicalizeExactClassExclusions(exclusions: List<CodeExclusion>): List<CodeExclusion> {
        val exactClassExclusions = exclusions.filter { it.reason in exactClassNameReasons }
        return exclusions.filterNot { it.reason in exactClassNameReasons } +
            exactClassExclusions.groupBy { it.key to it.reason }
                .values
                .map { candidates -> candidates.minBy(CodeExclusion::evidence) }
    }

    private fun resolveExternalCandidate(
        bytecode: BytecodeInventory,
        candidate: ExternalNameCandidate,
    ): List<CodeExclusion> = when (candidate.kind) {
        ExternalNameContractKind.GSON_UNEXPLICIT_FIELD -> resolveGsonCandidate(bytecode, candidate)
        ExternalNameContractKind.JAVASCRIPT_INTERFACE -> {
            val key = uniqueCandidate(candidate, sourceClasses(bytecode, candidate).flatMap { owner ->
                owner.methods.filter { it.name == candidate.symbol }.map(::methodKey)
            })
            listOf(exclusion(key, CodeExclusionReason.JAVASCRIPT_INTERFACE, candidate))
        }
        ExternalNameContractKind.JNI_NATIVE -> {
            val key = uniqueCandidate(candidate, sourceClasses(bytecode, candidate).flatMap { owner ->
                owner.methods.filter { it.name == candidate.symbol && it.access and Opcodes.ACC_NATIVE != 0 }.map(::methodKey)
            })
            listOf(
                exclusion(key, CodeExclusionReason.JNI_NATIVE, candidate),
                exclusion(classKey(bytecode.ownedClasses.getValue(key.owner)), CodeExclusionReason.JNI_NATIVE, candidate),
            )
        }
        ExternalNameContractKind.SERIALIZABLE -> {
            val owner = uniqueClassCandidate(bytecode, candidate)
            symbols(owner).map { exclusion(it, CodeExclusionReason.SERIALIZABLE, candidate) }
        }
        ExternalNameContractKind.OBJECTBOX_ENTITY -> {
            val owner = uniqueClassCandidate(bytecode, candidate)
            (listOf(classKey(owner)) + owner.fields.map(::fieldKey)).map {
                exclusion(it, CodeExclusionReason.OBJECTBOX_ENTITY, candidate)
            }
        }
        ExternalNameContractKind.EXPORTED_COMPONENT -> {
            val internalName = candidate.symbol.replace('.', '/')
            bytecode.ownedClasses[internalName]?.let { owner ->
                listOf(exclusion(classKey(owner), CodeExclusionReason.EXPORTED_COMPONENT, candidate))
            } ?: emptyList()
        }
        ExternalNameContractKind.MANIFEST_DECLARED_CLASS -> preserveOwnedClass(
            bytecode,
            candidate,
            CodeExclusionReason.MANIFEST_DECLARED_CLASS,
        )
        ExternalNameContractKind.LAYOUT_CUSTOM_VIEW -> preserveOwnedClass(
            bytecode,
            candidate,
            CodeExclusionReason.LAYOUT_CUSTOM_VIEW,
        )
        ExternalNameContractKind.GENERATED_VIEW_BINDING_REFLECTION,
        ExternalNameContractKind.PLATFORM_REFLECTION,
        ExternalNameContractKind.PLATFORM_RESOURCE_LOOKUP,
        -> emptyList()
    }

    private fun preserveOwnedClass(
        bytecode: BytecodeInventory,
        candidate: ExternalNameCandidate,
        reason: CodeExclusionReason,
    ): List<CodeExclusion> {
        val internalName = candidate.symbol.replace('.', '/')
        val owner = bytecode.ownedClasses[internalName] ?: return emptyList()
        return listOf(exclusion(classKey(owner), reason, candidate))
    }

    private fun resolveGsonCandidate(
        bytecode: BytecodeInventory,
        candidate: ExternalNameCandidate,
    ): List<CodeExclusion> {
        val candidatePath = candidateSourcePath(candidate)
        val owners = sourceClasses(bytecode.ownedClasses.values, candidatePath)
        require(owners.isNotEmpty()) {
            "Gson external contract has no exact owned source proof: " +
                "${candidate.sourceFile}:${candidate.line} ${candidate.symbol}"
        }
        val candidateModules = owners.mapNotNull(BytecodeClass::modulePath).toSet()
        require(candidateModules.size == 1) {
            "Gson external contract has ambiguous owned module source proof: " +
                "${candidate.sourceFile}:${candidate.line} ${candidate.symbol}"
        }
        val candidateModule = candidateModules.single()
        val candidateSourceFile = candidatePath.fileName.toString()
        val unprovenOwners = bytecode.hierarchyClasses.values.filter { owner ->
            owner.internalName !in bytecode.ownedClasses &&
                owner.modulePath == candidateModule &&
                (owner.sourceFile == candidateSourceFile || owner.sourcePath?.normalize()?.endsWith(candidatePath) == true) &&
                owner.fields.any { it.name == candidate.symbol }
        }
        require(unprovenOwners.isEmpty()) {
            "Gson external contract source proof includes unproven owned-module bytecode: " +
                "${candidate.sourceFile}:${candidate.line} ${candidate.symbol}"
        }
        val matches = owners.flatMap { owner ->
            owner.fields.filter { it.name == candidate.symbol }.map(::fieldKey)
        }
        if (matches.isEmpty()) return emptyList()
        return matches.map { key -> exclusion(key, CodeExclusionReason.GSON_UNEXPLICIT_FIELD, candidate) }
    }

    private fun sourceClasses(bytecode: BytecodeInventory, candidate: ExternalNameCandidate): List<BytecodeClass> =
        sourceClasses(bytecode.ownedClasses.values, candidateSourcePath(candidate))

    private fun candidateSourcePath(candidate: ExternalNameCandidate): Path {
        val candidatePath = Path.of(candidate.sourceFile.replace('\\', '/')).normalize()
        require(!candidatePath.isAbsolute && candidatePath.none { it.toString() == ".." }) {
            "external contract source path is not repository-relative: ${candidate.sourceFile}"
        }
        return candidatePath
    }

    private fun sourceClasses(classes: Collection<BytecodeClass>, candidatePath: Path): List<BytecodeClass> {
        return classes.filter { owner -> owner.sourcePath?.normalize()?.endsWith(candidatePath) == true }
    }

    private fun uniqueClassCandidate(bytecode: BytecodeInventory, candidate: ExternalNameCandidate): BytecodeClass =
        uniqueCandidate(candidate, sourceClasses(bytecode, candidate).filter { owner ->
            owner.internalName.substringAfterLast('/').substringAfterLast('$') == candidate.symbol
        })

    private fun <T> uniqueCandidate(candidate: ExternalNameCandidate, matches: List<T>): T {
        require(matches.isNotEmpty()) {
            "external contract resolved to zero owned symbols: ${candidate.kind} ${candidate.sourceFile}:${candidate.line} ${candidate.symbol}"
        }
        require(matches.size == 1) {
            "external contract resolved to multiple owned symbols: ${candidate.kind} ${candidate.sourceFile}:${candidate.line} ${candidate.symbol}"
        }
        return matches.single()
    }

    private fun exclusion(key: CodeSymbolKey, reason: CodeExclusionReason, candidate: ExternalNameCandidate) =
        CodeExclusion(key, reason, "${candidate.kind} at ${candidate.sourceFile}:${candidate.line}: ${candidate.symbol}")

    private fun unresolvedOwnedBytecode(bytecode: BytecodeInventory): List<CodeExclusion> =
        bytecode.hierarchyClasses.values.filter { owner ->
            owner.internalName !in bytecode.ownedClasses && owner.modulePath != null
        }.map { owner ->
            CodeExclusion(classKey(owner), CodeExclusionReason.UNPROVEN_SOURCE, "owned-module bytecode lacks closed source proof")
        }

    private fun androidViewPropertyMethods(bytecode: BytecodeInventory): List<CodeExclusion> =
        bytecode.ownedClasses.values
            .filter { owner -> owner.access and Opcodes.ACC_PUBLIC != 0 && extendsAndroidView(owner, bytecode) }
            .flatMap { owner ->
                owner.methods.filter(::isAndroidViewPropertyMethod).map { method ->
                    CodeExclusion(
                        methodKey(method),
                        CodeExclusionReason.ANDROID_VIEW_PROPERTY,
                        "public View subclass property-name contract",
                    )
                }
            }

    private fun eventBusSubscriberMethods(bytecode: BytecodeInventory): List<CodeExclusion> =
        bytecode.ownedClasses.values.flatMap { owner ->
            owner.methods.filter { method ->
                method.name != "<init>" &&
                    method.name != "<clinit>" &&
                    EVENTBUS_SUBSCRIBE_ANNOTATION_DESCRIPTOR in method.annotations
            }.map { method ->
                CodeExclusion(
                    methodKey(method),
                    CodeExclusionReason.EVENTBUS_SUBSCRIBER,
                    "EventBus @Subscribe method-name contract ($EVENTBUS_SUBSCRIBE_ANNOTATION_DESCRIPTOR)",
                )
            }
        }

    private fun externalKeepContractExclusions(bytecode: BytecodeInventory): List<CodeExclusion> =
        goRouterParamFieldExclusions(bytecode) +
            goRouterComponentExclusions(bytecode) +
            recyclerViewLayoutManagerExclusions(bytecode) +
            coordinatorLayoutBehaviorExclusions(bytecode) +
            androidStartupExclusions(bytecode)

    private fun goRouterParamFieldExclusions(bytecode: BytecodeInventory): List<CodeExclusion> =
        bytecode.ownedClasses.values.flatMap { owner ->
            owner.fields.filter { GOROUTER_PARAM_ANNOTATION_DESCRIPTOR in it.annotations }.map { field ->
                CodeExclusion(
                    fieldKey(field),
                    CodeExclusionReason.GOROUTER_PARAM_FIELD_KEEP_RULE,
                    "R8 keep-rule contract -keepclassmembers class * { @com.wyjson.router.annotation.Param <fields>; }: " +
                        "exact descriptor $GOROUTER_PARAM_ANNOTATION_DESCRIPTOR on ${field.owner}#${field.name}${field.descriptor}",
                )
            }
        }

    private fun goRouterComponentExclusions(bytecode: BytecodeInventory): List<CodeExclusion> =
        bytecode.ownedClasses.values.flatMap { owner ->
            GOROUTER_COMPONENT_INTERFACES.filter { interfaceName ->
                hasExactInterfaceAncestry(owner, interfaceName, bytecode)
            }.map { interfaceName ->
                CodeExclusion(
                    classKey(owner),
                    CodeExclusionReason.GOROUTER_COMPONENT_KEEP_RULE,
                    "R8 keep-rule contract -keepnames class * implements ${interfaceName.replace('/', '.')}: " +
                        "exact transitive interface ancestry $interfaceName",
                )
            }
        }

    private fun recyclerViewLayoutManagerExclusions(bytecode: BytecodeInventory): List<CodeExclusion> =
        bytecode.ownedClasses.values.filter { owner ->
            owner.access and Opcodes.ACC_PUBLIC != 0 &&
                hasExactSuperclassAncestry(owner, RECYCLERVIEW_LAYOUT_MANAGER, bytecode)
        }.map { owner ->
            CodeExclusion(
                classKey(owner),
                CodeExclusionReason.RECYCLERVIEW_LAYOUT_MANAGER_KEEP_RULE,
                "R8 keep-rule contract -keepnames public class * extends ${RECYCLERVIEW_LAYOUT_MANAGER.replace('/', '.')}: " +
                    "exact transitive superclass ancestry $RECYCLERVIEW_LAYOUT_MANAGER",
            )
        }

    private fun coordinatorLayoutBehaviorExclusions(bytecode: BytecodeInventory): List<CodeExclusion> =
        bytecode.ownedClasses.values.filter { owner ->
            owner.access and Opcodes.ACC_PUBLIC != 0 &&
                hasExactSuperclassAncestry(owner, COORDINATOR_LAYOUT_BEHAVIOR, bytecode)
        }.map { owner ->
            CodeExclusion(
                classKey(owner),
                CodeExclusionReason.COORDINATOR_LAYOUT_BEHAVIOR_KEEP_RULE,
                "R8 keep-rule contract -keep public class * extends " +
                    "${COORDINATOR_LAYOUT_BEHAVIOR.replace('/', '.')} { <init>(android.content.Context,android.util.AttributeSet); }: " +
                    "exact transitive superclass ancestry $COORDINATOR_LAYOUT_BEHAVIOR",
            )
        }

    private fun androidStartupExclusions(bytecode: BytecodeInventory): List<CodeExclusion> =
        bytecode.ownedClasses.values.flatMap { owner ->
            val contracts = buildList<Pair<String, String>> {
                if (
                    owner.access and Opcodes.ACC_PUBLIC != 0 &&
                    hasExactSuperclassAncestry(owner, ANDROID_STARTUP, bytecode)
                ) {
                    add("-keep public class * extends ${ANDROID_STARTUP.replace('/', '.')}" to ANDROID_STARTUP)
                }
                if (hasExactInterfaceAncestry(owner, STARTUP_PROVIDER_CONFIG, bytecode)) {
                    add("-keep class * implements ${STARTUP_PROVIDER_CONFIG.replace('/', '.')}" to STARTUP_PROVIDER_CONFIG)
                }
            }
            contracts.flatMap { (contract, matchedInternalName) ->
                symbols(owner).map { key ->
                    CodeExclusion(
                        key,
                        CodeExclusionReason.ANDROID_STARTUP_KEEP_RULE,
                        "R8 keep-rule contract $contract { *; }: exact matched startup hierarchy $matchedInternalName for ${owner.internalName}",
                    )
                }
            }
        }

    private fun hasExactSuperclassAncestry(
        owner: BytecodeClass,
        targetInternalName: String,
        bytecode: BytecodeInventory,
    ): Boolean {
        val visited = mutableSetOf<String>()
        var parentName = owner.superName
        while (parentName != null && visited.add(parentName)) {
            val parent = bytecode.hierarchyClasses[parentName] ?: return false
            if (parent.internalName == targetInternalName) return true
            parentName = parent.superName
        }
        return false
    }

    private fun hasExactInterfaceAncestry(
        owner: BytecodeClass,
        targetInternalName: String,
        bytecode: BytecodeInventory,
    ): Boolean {
        val pending = ArrayDeque<String>()
        val visitedClasses = mutableSetOf<String>()
        var current: BytecodeClass? = owner
        while (current != null && visitedClasses.add(current.internalName)) {
            current.interfaces.forEach(pending::addLast)
            current = current.superName?.let { parentName ->
                bytecode.hierarchyClasses[parentName] ?: return false
            }
        }
        val visitedInterfaces = mutableSetOf<String>()
        while (pending.isNotEmpty()) {
            val interfaceName = pending.removeFirst()
            if (!visitedInterfaces.add(interfaceName)) continue
            val interfaceType = bytecode.hierarchyClasses[interfaceName] ?: return false
            if (interfaceType.internalName == targetInternalName) return true
            interfaceType.interfaces.forEach(pending::addLast)
        }
        return false
    }

    private fun generatedEnumApiMethods(bytecode: BytecodeInventory): List<CodeExclusion> =
        bytecode.ownedClasses.values.flatMap { owner ->
            if (owner.access and Opcodes.ACC_ENUM == 0) {
                emptyList()
            } else {
                owner.methods.filter { method ->
                    method.access and Opcodes.ACC_PUBLIC != 0 &&
                        method.access and Opcodes.ACC_STATIC != 0 &&
                        (method.name == "values" && method.descriptor == "()[L${owner.internalName};" ||
                            method.name == "valueOf" && method.descriptor == "(Ljava/lang/String;)L${owner.internalName};")
                }.map { method ->
                    CodeExclusion(
                        methodKey(method),
                        CodeExclusionReason.GENERATED_ENUM_API,
                        "generated enum API contract: ${method.name}${method.descriptor}",
                    )
                }
            }
        }

    private fun callbackParameterKeepRuleMethods(bytecode: BytecodeInventory): List<CodeExclusion> =
        bytecode.ownedClasses.values.flatMap { owner ->
            owner.methods.mapNotNull { method ->
                callbackParameterKeepRuleContract(method)?.let { contract ->
                    val argument = Type.getArgumentTypes(method.descriptor).single()
                    CodeExclusion(
                        methodKey(method),
                        CodeExclusionReason.CALLBACK_PARAMETER_KEEP_RULE,
                        "callback parameter keep-rule contract $contract: ${argument.className} (${argument.descriptor})",
                    )
                }
            }
        }

    private fun callbackParameterKeepRuleContract(method: BytecodeMethod): String? {
        if (method.name == "<init>" || method.name == "<clinit>" || Type.getReturnType(method.descriptor) != Type.VOID_TYPE) {
            return null
        }
        val arguments = Type.getArgumentTypes(method.descriptor)
        val argument = arguments.singleOrNull() ?: return null
        if (argument.sort != Type.OBJECT) return null
        return when {
            CALLBACK_EVENT_PARAMETER.matches(argument.className) -> "**On*Event"
            CALLBACK_LISTENER_PARAMETER.matches(argument.className) -> "**On*Listener"
            else -> null
        }
    }

    private fun activityViewCallbackKeepRuleMethods(bytecode: BytecodeInventory): List<CodeExclusion> =
        bytecode.ownedClasses.values
            .filter { owner -> extendsAndroidActivity(owner, bytecode) }
            .flatMap { owner ->
                owner.methods.filter(::isActivityViewCallbackMethod).map { method ->
                    CodeExclusion(
                        methodKey(method),
                        CodeExclusionReason.ACTIVITY_VIEW_CALLBACK_KEEP_RULE,
                        "public Activity View callback keep-rule contract public void *(android.view.View): ${method.name}${method.descriptor}",
                    )
                }
            }

    private fun extendsAndroidActivity(owner: BytecodeClass, bytecode: BytecodeInventory): Boolean {
        val visited = mutableSetOf<String>()
        var parentName = owner.superName
        while (parentName != null && visited.add(parentName)) {
            val parent = bytecode.hierarchyClasses[parentName] ?: return false
            if (parent.internalName == "android/app/Activity") return true
            parentName = parent.superName
        }
        return false
    }

    private fun isActivityViewCallbackMethod(method: BytecodeMethod): Boolean {
        if (
            method.name == "<init>" ||
            method.name == "<clinit>" ||
            method.access and Opcodes.ACC_PUBLIC == 0 ||
            Type.getReturnType(method.descriptor) != Type.VOID_TYPE
        ) {
            return false
        }
        val arguments = Type.getArgumentTypes(method.descriptor)
        return arguments.size == 1 && arguments.single().descriptor == ANDROID_VIEW_DESCRIPTOR
    }

    private fun extendsAndroidView(owner: BytecodeClass, bytecode: BytecodeInventory): Boolean {
        val visited = mutableSetOf<String>()
        var parentName = owner.superName
        while (parentName != null && visited.add(parentName)) {
            val parent = bytecode.hierarchyClasses[parentName] ?: return false
            if (parent.internalName == "android/view/View") return true
            parentName = parent.superName
        }
        return false
    }

    private fun isAndroidViewPropertyMethod(method: BytecodeMethod): Boolean {
        val parameterCount = Type.getArgumentTypes(method.descriptor).size
        return (method.name.startsWith("set") && parameterCount == 1 && Type.getReturnType(method.descriptor) == Type.VOID_TYPE) ||
            (method.name.startsWith("get") && parameterCount == 0)
    }

    private fun symbols(owner: BytecodeClass): List<CodeSymbolKey> =
        listOf(classKey(owner)) + owner.fields.map(::fieldKey) + owner.methods.map(::methodKey)

    private companion object {
        const val EVENTBUS_SUBSCRIBE_ANNOTATION_DESCRIPTOR = "Lorg/greenrobot/eventbus/Subscribe;"
        const val GOROUTER_PARAM_ANNOTATION_DESCRIPTOR = "Lcom/wyjson/router/annotation/Param;"
        const val RECYCLERVIEW_LAYOUT_MANAGER = "androidx/recyclerview/widget/RecyclerView\$LayoutManager"
        const val COORDINATOR_LAYOUT_BEHAVIOR =
            "androidx/coordinatorlayout/widget/CoordinatorLayout\$Behavior"
        const val ANDROID_STARTUP = "com/rousetime/android_startup/AndroidStartup"
        const val STARTUP_PROVIDER_CONFIG = "com/rousetime/android_startup/provider/StartupProviderConfig"
        const val ANDROID_VIEW_DESCRIPTOR = "Landroid/view/View;"
        val GOROUTER_COMPONENT_INTERFACES = setOf(
            "com/wyjson/router/interfaces/IInterceptor",
            "com/wyjson/router/interfaces/IService",
        )
        val CALLBACK_EVENT_PARAMETER = Regex(".*On[^.]*Event")
        val CALLBACK_LISTENER_PARAMETER = Regex(".*On[^.]*Listener")
    }
}

internal fun classKey(owner: BytecodeClass) = CodeSymbolKey(
    kind = CodeSymbolKind.CLASS,
    owner = owner.internalName,
    name = owner.internalName.substringAfterLast('/'),
    descriptor = "L${owner.internalName};",
)

internal fun fieldKey(field: BytecodeField) = CodeSymbolKey(
    kind = CodeSymbolKind.FIELD,
    owner = field.owner,
    name = field.name,
    descriptor = field.descriptor,
)
