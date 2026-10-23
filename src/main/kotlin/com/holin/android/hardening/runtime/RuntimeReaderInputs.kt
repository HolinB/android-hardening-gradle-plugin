package com.holin.android.hardening.runtime

import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipFile

data class RuntimeReaderInputs(val entries: Map<String, ByteArray>, val hierarchy: Map<String, ByteArray>, val xml: Map<String, String>) {
    val classes: Map<String, ByteArray> = entries.filterKeys { it.endsWith(".class") }.mapKeys { it.key.removeSuffix(".class") }

    companion object {
        fun read(jars: Collection<File>, directories: Collection<File>, bootClasspath: Collection<File>, sources: Collection<File>, root: Path,
            namespace: String = "", symbols: File? = null): RuntimeReaderInputs {
            val entries = sortedMapOf<String, ByteArray>()
            fun add(name: String, bytes: ByteArray) {
                require(!name.startsWith('/') && name.split('/').none { it == "." || it == ".." }) { "invalid runtime program entry" }
                val prior = entries.putIfAbsent(name, bytes)
                require(prior == null || prior.contentEquals(bytes)) { "conflicting runtime program entry $name" }
            }
            jars.sortedBy { it.path }.forEach { jar -> ZipFile(jar).use { zip ->
                zip.entries().asSequence().filter { it.name.endsWith(".class") && it.name != "module-info.class" && !it.name.startsWith("META-INF/") }.forEach { entry ->
                    add(entry.name, zip.getInputStream(entry).use { it.readBytes() })
                }
            } }
            directories.sortedBy { it.path }.forEach { directory -> Files.walk(directory.toPath()).use { files -> files.forEach { file ->
                require(!Files.isSymbolicLink(file)) { "symbolic program class input" }
                if (Files.isRegularFile(file)) add(directory.toPath().relativize(file).toString().replace('\\', '/'), Files.readAllBytes(file))
            } } }
            val hierarchy = sortedMapOf<String, ByteArray>()
            bootClasspath.filter { it.isFile && it.extension == "jar" }.sortedBy { it.path }.forEach { jar -> ZipFile(jar).use { zip ->
                zip.entries().asSequence().filter { it.name.endsWith(".class") && it.name != "module-info.class" && !it.name.startsWith("META-INF/") }.forEach { entry ->
                    hierarchy.putIfAbsent(entry.name.removeSuffix(".class"), zip.getInputStream(entry).use { it.readBytes() })
                }
            } }
            if (symbols != null && namespace.isNotEmpty()) {
                val owner = namespace.replace('.', '/') + "/R\$string"
                val writer = org.objectweb.asm.ClassWriter(0)
                writer.visit(org.objectweb.asm.Opcodes.V1_8, org.objectweb.asm.Opcodes.ACC_PUBLIC, owner, null, "java/lang/Object", null)
                symbols.readLines().forEach { line ->
                    val parts = line.trim().split(Regex("\\s+"))
                    if (parts.size == 4 && parts[0] == "int" && parts[1] == "string") {
                        val id = parts[3].removePrefix("0x").toLong(16).toInt()
                        writer.visitField(org.objectweb.asm.Opcodes.ACC_PUBLIC or org.objectweb.asm.Opcodes.ACC_STATIC or org.objectweb.asm.Opcodes.ACC_FINAL,
                            parts[2], "I", null, id).visitEnd()
                    }
                }
                writer.visitEnd()
                hierarchy[owner] = writer.toByteArray()
            }
            val xml = sources.filter { it.isFile && it.extension == "xml" }.sortedBy { it.path }.associate {
                val path = it.toPath().toAbsolutePath().normalize()
                (if (path.startsWith(root)) root.relativize(path) else path).toString().replace('\\', '/') to it.readText()
            }
            return RuntimeReaderInputs(entries, hierarchy, xml)
        }
    }
}
