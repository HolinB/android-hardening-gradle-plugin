package com.holin.android.hardening.state

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path

object PortableStateMigrationDescriptorLoader {
    fun load(
        repositoryRoot: Path,
        descriptorFile: Path,
        projectKey: String,
        variant: String,
    ): PortableStateMigrationDescriptor {
        val root = repositoryRoot.toAbsolutePath().normalize()
        val descriptor = descriptorFile.toAbsolutePath().normalize()
        require(descriptor.startsWith(root) && descriptor != root) {
            "compatibility.migrationDescriptor escapes the repository boundary"
        }
        require(Files.isDirectory(root, NOFOLLOW_LINKS) && !Files.isSymbolicLink(root)) {
            "compatibility.migrationDescriptor repository root is unsafe"
        }
        var current = root
        root.relativize(descriptor).forEach { component ->
            current = current.resolve(component)
            require(!Files.isSymbolicLink(current)) {
                "compatibility.migrationDescriptor path contains a symlink: $current"
            }
        }
        require(Files.isRegularFile(descriptor, NOFOLLOW_LINKS)) {
            "compatibility.migrationDescriptor is missing or is not a non-symlink regular file: $descriptor"
        }
        require(Files.size(descriptor) in 1..MAX_DESCRIPTOR_BYTES) {
            "compatibility.migrationDescriptor has an invalid size"
        }
        return PortableStateMigrationDescriptorCodec.decode(Files.readString(descriptor)).also { migration ->
            require(migration.projectKey == projectKey) {
                "compatibility.migrationDescriptor projectKey does not match $projectKey"
            }
            require(migration.variant == variant) {
                "compatibility.migrationDescriptor variant does not match $variant"
            }
        }
    }

    private const val MAX_DESCRIPTOR_BYTES = 1024L * 1024L
}
