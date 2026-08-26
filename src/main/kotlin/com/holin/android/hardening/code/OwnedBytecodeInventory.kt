package com.holin.android.hardening.code

import com.holin.android.hardening.HardeningOwnership
import com.holin.android.hardening.inventory.OwnedDexInventoryBuilder
import com.holin.android.hardening.inventory.OwnedSourceClass
import com.holin.android.hardening.inventory.OwnedSourceClassKind
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipException
import java.util.zip.ZipFile
import org.objectweb.asm.AnnotationVisitor
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.FieldVisitor
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

/** Collects bytecode only when its source and producing component prove first-party ownership. */
class OwnedBytecodeInventoryBuilder(
    repositoryRoot: Path,
    private val ownership: HardeningOwnership,
) {
    private val root = repositoryRoot.toAbsolutePath().normalize()

    fun build(inputs: Collection<BytecodeInput>): BytecodeInventory {
        val candidates = inputs.sortedWith(compareBy<BytecodeInput>({ it.modulePath ?: "~" }, { it.path.toString() }))
            .flatMap { input -> readClasses(input).map { bytecode -> BytecodeCandidate(bytecode, input) } }
        val classesByName = candidates.groupBy { candidate -> candidate.bytecode.internalName }
        val duplicates = classesByName.filterValues { it.size > 1 }
        val multipleOwnedProducers = duplicates.filterValues { group ->
            group.count { candidate -> candidate.input.modulePath != null } > 1
        }
        require(multipleOwnedProducers.isEmpty()) {
            "multiple owned bytecode producers: ${multipleOwnedProducers.keys.sorted()}"
        }
        val conflictingOwnedCopies = duplicates.filterValues { group ->
            val owned = group.singleOrNull { candidate -> candidate.input.modulePath != null }
                ?: return@filterValues false
            group.any { candidate -> candidate !== owned && !sameDefinition(owned.bytecode, candidate.bytecode) }
        }
        require(conflictingOwnedCopies.isEmpty()) {
            "conflicting owned bytecode classes: ${conflictingOwnedCopies.keys.sorted()}"
        }
        val invalidHierarchyDuplicates = duplicates.filterValues { group ->
            if (group.any { candidate -> candidate.input.modulePath != null }) return@filterValues false
            val precedences = group.map { candidate -> candidate.input.hierarchyPrecedence }
            precedences.any { it == null } || precedences.filterNotNull().distinct().size != precedences.size
        }
        require(invalidHierarchyDuplicates.isEmpty()) {
            "duplicate hierarchy classes require explicit unique precedence: ${invalidHierarchyDuplicates.keys.sorted()}"
        }
        val selected = classesByName.values.map { group ->
            group.singleOrNull { candidate -> candidate.input.modulePath != null }
                ?: group.minBy { candidate -> candidate.input.hierarchyPrecedence ?: Int.MAX_VALUE }
        }.sortedBy { candidate -> candidate.bytecode.internalName }
        val classes = selected.map(BytecodeCandidate::bytecode)

        val sourceInventory = OwnedDexInventoryBuilder(root, ownership).sourceInventory()
        val proof = OwnedSourceProof(sourceInventory)
        val roots = proof.provenRoots(classes)
        val owned = classes.asSequence()
            .mapNotNull { bytecode ->
            proof.provenSource(bytecode, roots)?.let { source ->
                bytecode.internalName to bytecode.withSourcePath(source.source)
            }
            }
            .toMap()
        require(owned.isNotEmpty()) { "owned bytecode inventory is empty" }
        require(owned.values.mapNotNull(BytecodeClass::modulePath).toSet() == ownership.modulePaths) {
            "owned bytecode artifacts are incomplete"
        }
        val hierarchy = classes.associateBy(BytecodeClass::internalName)
        val programClasses = selected.asSequence()
            .filter { candidate -> candidate.input.programInput }
            .map { candidate -> candidate.bytecode.internalName }
            .toSortedSet()
        return BytecodeInventory(owned.toSortedMap(), hierarchy.toSortedMap(), programClasses)
    }

    private fun readClasses(input: BytecodeInput): List<BytecodeClass> {
        require(input.modulePath == null || input.modulePath in ownership.modulePaths) {
            "bytecode input is outside the owned module scope: ${input.modulePath}"
        }
        val path = input.path.toAbsolutePath().normalize()
        require(!Files.isSymbolicLink(input.path) && !Files.isSymbolicLink(path)) {
            "bytecode input must not be a symbolic link: ${input.path}"
        }
        if (input.modulePath != null) requireOwnedInputPath(path)
        return when {
            Files.isDirectory(path) -> readDirectory(path, input.modulePath)
            Files.isRegularFile(path) -> readJar(path, input.modulePath)
            else -> throw IllegalArgumentException("bytecode input is neither a directory nor a regular file: $path")
        }
    }

    private fun readDirectory(directory: Path, modulePath: String?): List<BytecodeClass> = Files.walk(directory).use { paths ->
        paths.sorted().forEach { path ->
            require(!Files.isSymbolicLink(path)) { "bytecode directory contains a symbolic link: $path" }
        }
        Files.walk(directory).use { secondPass ->
            secondPass.filter(Files::isRegularFile)
                .filter { it.fileName.toString().endsWith(CLASS_SUFFIX) }
                .sorted()
                .filter { path ->
                    val relative = directory.relativize(path).toString().replace(path.fileSystem.separator, "/")
                    !isVersionedClass(relative) && !isNonTypeClass(relative)
                }
                .map { path ->
                    val relative = directory.relativize(path).toString().replace(path.fileSystem.separator, "/")
                    validateClassEntry(relative)
                    readClass(Files.readAllBytes(path), relative.removeSuffix(CLASS_SUFFIX), modulePath, path)
                }
                .toList()
        }
    }

    private fun readJar(path: Path, modulePath: String?): List<BytecodeClass> = try {
        ZipFile(path.toFile()).use { zip ->
            val entries = zip.entries().asSequence().toList().sortedBy { it.name }
            entries.forEach { entry -> validateZipEntry(entry.name) }
            val duplicateEntries = entries.groupBy { it.name }.filterValues { it.size > 1 }.keys
            require(duplicateEntries.isEmpty()) { "duplicate bytecode ZIP entries: ${duplicateEntries.sorted()}" }
            entries.asSequence()
                .filterNot { it.isDirectory || isVersionedClass(it.name) || isNonTypeClass(it.name) }
                .filter { it.name.endsWith(CLASS_SUFFIX) }
                .map { entry ->
                    val internalName = validateClassEntry(entry.name)
                    zip.getInputStream(entry).use { bytes -> readClass(bytes.readBytes(), internalName, modulePath, null) }
                }
                .toList()
        }
    } catch (failure: ZipException) {
        throw IllegalArgumentException("invalid bytecode ZIP: $path", failure)
    }

    private fun readClass(
        bytes: ByteArray,
        expectedInternalName: String,
        modulePath: String?,
        sourcePath: Path?,
    ): BytecodeClass {
        val collector = BytecodeCollector(modulePath, sourcePath)
        try {
            ClassReader(bytes).accept(collector, ClassReader.SKIP_CODE or ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
        } catch (failure: IllegalArgumentException) {
            throw IllegalArgumentException("invalid bytecode class $expectedInternalName", failure)
        }
        val bytecode = collector.freeze().withSourceFile(readSourceFile(bytes))
        require(bytecode.internalName == expectedInternalName) {
            "bytecode class name mismatch: entry $expectedInternalName, header ${bytecode.internalName}"
        }
        return bytecode
    }

    /** SourceFile is debug metadata, so it requires a separate no-code read from the main skipped scan. */
    private fun readSourceFile(bytes: ByteArray): String? {
        val collector = SourceFileCollector()
        try {
            ClassReader(bytes).accept(collector, ClassReader.SKIP_CODE or ClassReader.SKIP_FRAMES)
        } catch (failure: IllegalArgumentException) {
            throw IllegalArgumentException("invalid bytecode source metadata", failure)
        }
        return collector.sourceFile
    }

    private fun validateZipEntry(name: String) {
        require(name.isNotBlank() && !name.startsWith('/') && '\\' !in name) { "unsafe bytecode ZIP entry: $name" }
        val path = name.removeSuffix("/")
        require(path.isNotBlank() && path.split('/').none { it.isBlank() || it == "." || it == ".." }) {
            "unsafe bytecode ZIP entry: $name"
        }
    }

    private fun validateClassEntry(name: String): String {
        validateZipEntry(name)
        require(name.endsWith(CLASS_SUFFIX)) { "bytecode entry is not a class: $name" }
        return name.removeSuffix(CLASS_SUFFIX).also { internalName ->
            require(JvmClassName.isInternal(internalName)) {
                "invalid bytecode class entry: $name"
            }
        }
    }

    private fun requireNoRepositorySymlinks(path: Path) {
        var current = root
        require(!Files.isSymbolicLink(current)) { "owned bytecode input contains a symbolic link: $current" }
        root.relativize(path).forEach { component ->
            current = current.resolve(component)
            require(!Files.isSymbolicLink(current)) { "owned bytecode input contains a symbolic link: $current" }
        }
    }

    private fun requireOwnedInputPath(path: Path) {
        if (path.startsWith(root)) {
            requireNoRepositorySymlinks(path)
            return
        }
        if (!Files.exists(path)) return
        require(!path.toRealPath().startsWith(root.toRealPath())) {
            "owned bytecode input reaches the repository through a symbolic link: $path"
        }
    }

    private companion object {
        const val CLASS_SUFFIX = ".class"
    }

    private data class BytecodeCandidate(val bytecode: BytecodeClass, val input: BytecodeInput)

    private fun sameDefinition(first: BytecodeClass, second: BytecodeClass): Boolean =
        first.internalName == second.internalName &&
            first.sourceFile == second.sourceFile &&
            first.access == second.access &&
            first.superName == second.superName &&
            first.interfaces == second.interfaces &&
            first.annotations == second.annotations &&
            first.fields == second.fields &&
            first.methods == second.methods &&
            first.kotlinMetadataKind == second.kotlinMetadataKind &&
            first.kotlinMetadataExtraString == second.kotlinMetadataExtraString

    private fun isNonTypeClass(name: String): Boolean {
        val simpleName = name.substringAfterLast('/').removeSuffix(CLASS_SUFFIX)
        return name == "module-info.class" || simpleName == "package-info" ||
            simpleName == "R" || simpleName.startsWith("R${'$'}")
    }

    private fun isVersionedClass(name: String): Boolean {
        val parts = name.split('/')
        return parts.size >= 4 && parts[0] == "META-INF" && parts[1] == "versions" && parts[2].all(Char::isDigit)
    }

}

private class OwnedSourceProof(sources: List<OwnedSourceClass>) {
    private val sources = sources.sortedWith(
        compareBy(
            OwnedSourceClass::module,
            OwnedSourceClass::originalDescriptor,
            { it.source.toString() },
            { it.kind.ordinal },
        ),
    )

    fun provenRoots(classes: List<BytecodeClass>): List<ProvenRoot> {
        val declaredRoots = sources.asSequence()
            .filter { it.kind == OwnedSourceClassKind.DECLARED_TYPE }
            .map { source ->
                ProvenRoot(source.originalDescriptor.toInternalName(), source.module, source.kind, listOf(source))
            }
        val bytecodeRoots = classes.asSequence().mapNotNull { bytecode ->
            when (bytecode.kotlinMetadataKind) {
                2 -> proveFileFacade(bytecode)?.let { source ->
                    ProvenRoot(bytecode.internalName, requireNotNull(bytecode.modulePath), source.kind, listOf(source))
                }
                4 -> proveMultifileFacadeSources(bytecode)?.let { rootSources ->
                    ProvenRoot(
                        bytecode.internalName,
                        requireNotNull(bytecode.modulePath),
                        OwnedSourceClassKind.KOTLIN_MULTIFILE_FACADE,
                        rootSources,
                    )
                }
                5 -> proveMultifilePart(bytecode)?.let { source ->
                    ProvenRoot(bytecode.internalName, requireNotNull(bytecode.modulePath), source.kind, listOf(source))
                }
                else -> null
            }
        }
        return (declaredRoots + bytecodeRoots)
            .sortedWith(compareBy(ProvenRoot::module, ProvenRoot::internalName, { it.kind.ordinal }))
            .toList()
    }

    fun provenSource(bytecode: BytecodeClass, roots: List<ProvenRoot>): OwnedSourceClass? {
        val module = bytecode.modulePath ?: return null
        val sourceFile = bytecode.sourceFile ?: return null
        proveExactSource(bytecode)?.let { return it }
        if (bytecode.kotlinMetadataKind !in DEPENDENT_KINDS) return null
        val candidates = roots.filter { root ->
            root.module == module && bytecode.internalName.startsWith(root.internalName + '$') &&
                (
                    bytecode.kotlinMetadataKind != null ||
                        root.kind == OwnedSourceClassKind.DECLARED_TYPE &&
                        root.sources.singleOrNull()?.kotlinSourcePart == null
                ) &&
                root.sources.any { it.source.fileName.toString() == sourceFile }
        }
        val longest = candidates.maxOfOrNull { it.internalName.length } ?: return null
        val root = candidates.singleOrNull { it.internalName.length == longest } ?: return null
        return root.sources.singleOrNull { it.source.fileName.toString() == sourceFile }
    }

    private fun proveExactSource(bytecode: BytecodeClass): OwnedSourceClass? = when (bytecode.kotlinMetadataKind) {
        null, 1 -> proveDeclaredType(bytecode)
        2 -> proveFileFacade(bytecode)
        4 -> proveMultifileFacadeSources(bytecode)?.singleOrNull { source ->
            source.source.fileName.toString() == bytecode.sourceFile
        }
        5 -> proveMultifilePart(bytecode)
        else -> null
    }

    private fun proveDeclaredType(bytecode: BytecodeClass): OwnedSourceClass? {
        val module = bytecode.modulePath ?: return null
        val sourceFile = bytecode.sourceFile ?: return null
        return sources.singleOrNull { source ->
            source.kind == OwnedSourceClassKind.DECLARED_TYPE && source.module == module &&
                source.source.fileName.toString() == sourceFile &&
                bytecode.internalName == source.originalDescriptor.toInternalName()
        }
    }

    private fun proveFileFacade(bytecode: BytecodeClass): OwnedSourceClass? {
        val module = bytecode.modulePath ?: return null
        val sourceFile = bytecode.sourceFile ?: return null
        return sources.singleOrNull { source ->
            source.kind == OwnedSourceClassKind.KOTLIN_FILE_FACADE &&
                source.module == module && source.source.fileName.toString() == sourceFile &&
                source.kotlinSourcePart?.hasTopLevelJvmDeclaration == true &&
                !source.kotlinSourcePart.multifileClass &&
                source.originalDescriptor.toInternalName() == bytecode.internalName &&
                source.kotlinSourcePart.expectedFacadeDescriptor == source.originalDescriptor
        }
    }

    private fun proveMultifileFacadeSources(bytecode: BytecodeClass): List<OwnedSourceClass>? {
        val module = bytecode.modulePath ?: return null
        val sourceFile = bytecode.sourceFile ?: return null
        val candidates = sources.filter { source ->
            source.kind == OwnedSourceClassKind.KOTLIN_MULTIFILE_FACADE && source.module == module &&
                source.originalDescriptor.toInternalName() == bytecode.internalName &&
                source.kotlinSourcePart?.hasTopLevelJvmDeclaration == true &&
                source.kotlinSourcePart.multifileClass && source.kotlinSourcePart.fileJvmName != null &&
                source.kotlinSourcePart.expectedFacadeDescriptor == source.originalDescriptor
        }
        if (candidates.map(OwnedSourceClass::source).distinct().size < 2 ||
            candidates.count { it.source.fileName.toString() == sourceFile } != 1
        ) {
            return null
        }
        return candidates
    }

    private fun proveMultifilePart(bytecode: BytecodeClass): OwnedSourceClass? {
        val module = bytecode.modulePath ?: return null
        val sourceFile = bytecode.sourceFile ?: return null
        return sources.singleOrNull { source ->
            source.kind == OwnedSourceClassKind.KOTLIN_MULTIFILE_PART &&
                source.module == module && source.source.fileName.toString() == sourceFile &&
                source.kotlinSourcePart?.hasTopLevelJvmDeclaration == true &&
                source.kotlinSourcePart.multifileClass && source.kotlinSourcePart.fileJvmName != null &&
                source.originalDescriptor.toInternalName() == bytecode.internalName &&
                source.kotlinSourcePart.expectedPartDescriptor == source.originalDescriptor &&
                source.kotlinSourcePart.expectedFacadeDescriptor.toInternalName() == bytecode.kotlinMetadataExtraString
        }
    }

    private fun String.toInternalName(): String = removePrefix("L").removeSuffix(";")

    data class ProvenRoot(
        val internalName: String,
        val module: String,
        val kind: OwnedSourceClassKind,
        val sources: List<OwnedSourceClass>,
    )

    private companion object {
        val DEPENDENT_KINDS = setOf(null, 1, 3)
    }
}

private class BytecodeCollector(
    private val modulePath: String?,
    private val sourcePath: Path?,
) : ClassVisitor(Opcodes.ASM9) {
    private lateinit var internalName: String
    private var access: Int = 0
    private var superName: String? = null
    private var interfaces: List<String> = emptyList()
    private val annotations = sortedSetOf<String>()
    private val fields = mutableListOf<BytecodeField>()
    private val methods = mutableListOf<BytecodeMethod>()
    private var kotlinMetadataKind: Int? = null
    private var kotlinMetadataExtraString: String? = null

    override fun visit(
        version: Int,
        access: Int,
        name: String,
        signature: String?,
        superName: String?,
        interfaces: Array<out String>?,
    ) {
        internalName = name
        this.access = access
        this.superName = superName
        this.interfaces = interfaces?.toList().orEmpty()
    }

    override fun visitAnnotation(descriptor: String, visible: Boolean): AnnotationVisitor? {
        annotations += descriptor
        return if (descriptor == KOTLIN_METADATA) object : AnnotationVisitor(Opcodes.ASM9) {
            override fun visit(name: String?, value: Any?) {
                if (name == "k") kotlinMetadataKind = value as? Int
                if (name == "xs") kotlinMetadataExtraString = value as? String
            }
        } else null
    }

    override fun visitField(
        access: Int,
        name: String,
        descriptor: String,
        signature: String?,
        value: Any?,
    ): FieldVisitor = object : FieldVisitor(Opcodes.ASM9) {
        private val fieldAnnotations = sortedSetOf<String>()

        override fun visitAnnotation(descriptor: String, visible: Boolean): AnnotationVisitor? {
            fieldAnnotations += descriptor
            return null
        }

        override fun visitEnd() {
            fields += BytecodeField(internalName, name, descriptor, access, fieldAnnotations.toSet())
        }
    }

    override fun visitMethod(
        access: Int,
        name: String,
        descriptor: String,
        signature: String?,
        exceptions: Array<out String>?,
    ): MethodVisitor = object : MethodVisitor(Opcodes.ASM9) {
        private val methodAnnotations = sortedSetOf<String>()

        override fun visitAnnotation(descriptor: String, visible: Boolean): AnnotationVisitor? {
            methodAnnotations += descriptor
            return null
        }

        override fun visitEnd() {
            methods += BytecodeMethod(internalName, name, descriptor, access, methodAnnotations.toSet())
        }
    }

    fun freeze(): BytecodeClass = BytecodeClass(
        internalName = internalName,
        modulePath = modulePath,
        sourceFile = null,
        sourcePath = sourcePath,
        access = access,
        superName = superName,
        interfaces = interfaces.toList(),
        annotations = annotations.toSet(),
        fields = fields.toList(),
        methods = methods.toList(),
        kotlinMetadataKind = kotlinMetadataKind,
        kotlinMetadataExtraString = kotlinMetadataExtraString,
    )

    private companion object {
        const val KOTLIN_METADATA = "Lkotlin/Metadata;"
    }
}

private class SourceFileCollector : ClassVisitor(Opcodes.ASM9) {
    var sourceFile: String? = null
        private set

    override fun visitSource(source: String?, debug: String?) {
        sourceFile = source
    }
}
