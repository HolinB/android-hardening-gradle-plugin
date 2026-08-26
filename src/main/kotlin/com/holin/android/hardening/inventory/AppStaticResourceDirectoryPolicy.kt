package com.holin.android.hardening.inventory

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.Locale

/** Accepts only real, production app resource directories contained by the repository. */
class AppStaticResourceDirectoryPolicy(
    repositoryRoot: Path,
    appDirectory: Path,
) {
    private val root = repositoryRoot.toAbsolutePath().normalize()
    private val app = appDirectory.toAbsolutePath().normalize()

    fun accepts(directory: Path): Boolean {
        val path = directory.toAbsolutePath().normalize()
        if (!path.startsWith(root) || !path.startsWith(app) || path == app) return false
        if (containsExcludedComponent(root.relativize(path))) return false

        var ancestor = root
        if (Files.isSymbolicLink(ancestor)) return false
        root.relativize(path).forEach { component ->
            ancestor = ancestor.resolve(component)
            if (Files.isSymbolicLink(ancestor)) return false
        }
        return Files.isDirectory(path, NOFOLLOW_LINKS)
    }

    private fun containsExcludedComponent(path: Path): Boolean = path.iterator().asSequence()
        .map { component -> component.toString().lowercase(Locale.ROOT) }
        .any(EXCLUDED_COMPONENTS::contains)

    private companion object {
        val EXCLUDED_COMPONENTS = setOf("build", "generated", "test", "androidtest", "testfixtures")
    }
}
