package com.holin.android.hardening

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.gradle.testfixtures.ProjectBuilder

class HardcodedReferenceScopeTest {
    @Test
    fun `DSL exposes provider backed defaults for every hardcoded reference kind`() {
        val project = ProjectBuilder.builder().build()
        val extension = project.objects.newInstance(
            AndroidHardeningExtension::class.java,
            project.objects,
            project.layout,
        )

        val scope = extension.ownership.hardcodedReferences.resolve()

        assertEquals(HardcodedReferenceKind.values().toSet(), scope.kinds)
        assertEquals(setOf("**/*.kt", "**/*.java", "**/*.xml"), scope.includeGlobs)
        assertEquals(setOf("**/test/**", "**/androidTest/**"), scope.excludeGlobs)
        assertTrue(scope.failOnUnresolvedOwnedReference)
        assertFalse(scope.requireExplicitIncludeMatches)
        assertEquals(
            listOf("**/*.kt", "**/*.java", "**/*.xml"),
            extension.ownership.hardcodedReferences.includeGlobs.get(),
        )
    }

    @Test
    fun `explicit default looking includes retain explicit provenance`() {
        val project = ProjectBuilder.builder().build()
        val extension = project.objects.newInstance(
            AndroidHardeningExtension::class.java,
            project.objects,
            project.layout,
        )
        extension.ownership.hardcodedReferences.includeGlobs.set(
            listOf("**/*.kt", "**/*.java", "**/*.xml"),
        )

        val scope = extension.ownership.hardcodedReferences.resolve()

        assertTrue(extension.ownership.hardcodedReferences.includeGlobs.isPresent)
        assertTrue(scope.requireExplicitIncludeMatches)
    }

    @Test
    fun `explicit default looking addAll includes retain explicit provenance`() {
        val project = ProjectBuilder.builder().build()
        val extension = project.objects.newInstance(
            AndroidHardeningExtension::class.java,
            project.objects,
            project.layout,
        )
        extension.ownership.hardcodedReferences.includeGlobs.addAll(
            listOf("**/*.kt", "**/*.java", "**/*.xml"),
        )

        val scope = extension.ownership.hardcodedReferences.resolve()

        assertEquals(setOf("**/*.kt", "**/*.java", "**/*.xml"), scope.includeGlobs)
        assertTrue(scope.requireExplicitIncludeMatches)
    }
}
