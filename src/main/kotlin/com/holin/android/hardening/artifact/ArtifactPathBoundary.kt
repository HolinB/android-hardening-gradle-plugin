package com.holin.android.hardening.artifact

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path

/**
 * Keeps every generated or consumed hardening artifact below one trusted build
 * directory and rejects symlinks instead of following them.
 */
internal class ArtifactPathBoundary(boundary: Path) {
    private val boundary = boundary.toAbsolutePath().normalize()

    fun requireInput(path: Path): Path {
        val absolute = requireDescendant(path)
        requireSafeDirectories(requireNotNull(absolute.parent), createMissing = false)
        require(Files.isRegularFile(absolute, NOFOLLOW_LINKS) && !Files.isSymbolicLink(absolute)) {
            "hardening artifact input is missing or unsafe"
        }
        return absolute
    }

    fun prepareOutput(path: Path): Path {
        val absolute = requireDescendant(path)
        requireSafeDirectories(requireNotNull(absolute.parent), createMissing = true)
        if (Files.exists(absolute, NOFOLLOW_LINKS)) {
            require(Files.isRegularFile(absolute, NOFOLLOW_LINKS) && !Files.isSymbolicLink(absolute)) {
                "hardening artifact output is unsafe"
            }
        }
        return absolute
    }

    private fun requireDescendant(path: Path): Path {
        val absolute = path.toAbsolutePath().normalize()
        require(absolute.startsWith(boundary) && absolute != boundary) {
            "hardening artifact path must stay below its configured build directory"
        }
        return absolute
    }

    private fun requireSafeDirectories(parent: Path, createMissing: Boolean) {
        require(parent.startsWith(boundary)) {
            "hardening artifact parent must stay below its configured build directory"
        }
        if (!Files.exists(boundary, NOFOLLOW_LINKS)) {
            require(createMissing) { "hardening artifact build directory is missing" }
            Files.createDirectories(boundary)
        }
        requireSafeDirectory(boundary)

        var current = boundary
        boundary.relativize(parent).forEach { component ->
            current = current.resolve(component)
            if (!Files.exists(current, NOFOLLOW_LINKS)) {
                require(createMissing) { "hardening artifact parent is missing" }
                Files.createDirectory(current)
            }
            requireSafeDirectory(current)
        }
    }

    private fun requireSafeDirectory(path: Path) {
        require(!Files.isSymbolicLink(path) && Files.isDirectory(path, NOFOLLOW_LINKS)) {
            "symlink or non-directory is not allowed in a hardening artifact path"
        }
    }
}
