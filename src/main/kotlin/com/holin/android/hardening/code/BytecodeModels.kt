package com.holin.android.hardening.code

import java.nio.file.Path
import java.util.Collections
import java.util.LinkedHashMap
import java.util.LinkedHashSet

private fun <T> immutableList(values: Collection<T>): List<T> = Collections.unmodifiableList(ArrayList(values))
private fun <T> immutableSet(values: Collection<T>): Set<T> = Collections.unmodifiableSet(LinkedHashSet(values))
private fun <K, V> immutableMap(values: Map<K, V>): Map<K, V> = Collections.unmodifiableMap(LinkedHashMap(values))

class BytecodeInput(
    path: Path,
    val modulePath: String?,
    val hierarchyPrecedence: Int? = null,
    val programInput: Boolean = false,
) {
    init {
        require(hierarchyPrecedence == null || hierarchyPrecedence >= 0) {
            "hierarchy precedence must be non-negative"
        }
        require(!programInput || modulePath != null || hierarchyPrecedence != null) {
            "non-project program input requires explicit hierarchy precedence"
        }
    }

    val path: Path = path.toAbsolutePath().normalize()
    override fun equals(other: Any?) = other is BytecodeInput && path == other.path && modulePath == other.modulePath &&
        hierarchyPrecedence == other.hierarchyPrecedence && programInput == other.programInput
    override fun hashCode() = listOf(path, modulePath, hierarchyPrecedence, programInput).hashCode()
    override fun toString() =
        "BytecodeInput(path=$path, modulePath=$modulePath, hierarchyPrecedence=$hierarchyPrecedence, " +
            "programInput=$programInput)"
}

class BytecodeField(val owner: String, val name: String, val descriptor: String, val access: Int, annotations: Collection<String>) {
    val annotations: Set<String> = immutableSet(annotations)
    override fun equals(other: Any?) = other is BytecodeField && owner == other.owner && name == other.name &&
        descriptor == other.descriptor && access == other.access && annotations == other.annotations
    override fun hashCode() = listOf(owner, name, descriptor, access, annotations).hashCode()
}

class BytecodeMethod(val owner: String, val name: String, val descriptor: String, val access: Int, annotations: Collection<String>) {
    val annotations: Set<String> = immutableSet(annotations)
    override fun equals(other: Any?) = other is BytecodeMethod && owner == other.owner && name == other.name &&
        descriptor == other.descriptor && access == other.access && annotations == other.annotations
    override fun hashCode() = listOf(owner, name, descriptor, access, annotations).hashCode()
}

class BytecodeClass(
    val internalName: String,
    val modulePath: String?,
    val sourceFile: String?,
    val sourcePath: Path?,
    val access: Int,
    val superName: String?,
    interfaces: Collection<String>,
    annotations: Collection<String>,
    fields: Collection<BytecodeField>,
    methods: Collection<BytecodeMethod>,
    val kotlinMetadataKind: Int? = null,
    val kotlinMetadataExtraString: String? = null,
) {
    val interfaces: List<String> = immutableList(interfaces)
    val annotations: Set<String> = immutableSet(annotations)
    val fields: List<BytecodeField> = immutableList(fields)
    val methods: List<BytecodeMethod> = immutableList(methods)
    fun withSourceFile(file: String?) = BytecodeClass(internalName, modulePath, file, sourcePath, access, superName,
        interfaces, annotations, fields, methods, kotlinMetadataKind, kotlinMetadataExtraString)
    fun withSourcePath(path: Path) = BytecodeClass(internalName, modulePath, sourceFile, path, access, superName,
        interfaces, annotations, fields, methods, kotlinMetadataKind, kotlinMetadataExtraString)
    override fun equals(other: Any?) = other is BytecodeClass && internalName == other.internalName &&
        modulePath == other.modulePath && sourceFile == other.sourceFile && sourcePath == other.sourcePath &&
        access == other.access && superName == other.superName && interfaces == other.interfaces &&
        annotations == other.annotations && fields == other.fields && methods == other.methods &&
        kotlinMetadataKind == other.kotlinMetadataKind && kotlinMetadataExtraString == other.kotlinMetadataExtraString
    override fun hashCode() = listOf(internalName, modulePath, sourceFile, sourcePath, access, superName, interfaces,
        annotations, fields, methods, kotlinMetadataKind, kotlinMetadataExtraString).hashCode()
}

class BytecodeInventory(
    ownedClasses: Map<String, BytecodeClass>,
    hierarchyClasses: Map<String, BytecodeClass>,
    programClasses: Collection<String> = emptySet(),
) {
    val ownedClasses: Map<String, BytecodeClass> = immutableMap(ownedClasses)
    val hierarchyClasses: Map<String, BytecodeClass> = immutableMap(hierarchyClasses)
    val programClasses: Set<String> = immutableSet(programClasses)
    init {
        require(this.programClasses.all(this.hierarchyClasses::containsKey)) {
            "program classes must belong to the selected hierarchy"
        }
    }
    override fun equals(other: Any?) = other is BytecodeInventory &&
        ownedClasses == other.ownedClasses && hierarchyClasses == other.hierarchyClasses &&
        programClasses == other.programClasses
    override fun hashCode() = 31 * (31 * ownedClasses.hashCode() + hierarchyClasses.hashCode()) + programClasses.hashCode()
}
