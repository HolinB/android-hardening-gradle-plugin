package com.holin.android.hardening.artifact

import com.holin.android.hardening.HardcodedReferenceKind
import com.holin.android.hardening.audit.HardcodedReferenceFinding
import com.holin.android.hardening.audit.HardeningSourceAudit
import com.holin.android.hardening.resources.ResourceType
import kotlin.test.Test
import kotlin.test.assertEquals

class ScopedExternallyNamedResourcesTest {
    @Test
    fun `only enabled scoped resource findings protect resource plan names`() {
        val enabled = HardeningSourceAudit(
            emptyList(),
            emptyList(),
            emptyList(),
            emptyList(),
            emptyList(),
            emptyList(),
            listOf(
                HardcodedReferenceFinding(
                    HardcodedReferenceKind.RESOURCE_NAME,
                    "app/src/main/java/com/example/Contract.java",
                    5,
                    "com.example.namespace:drawable/hero",
                ),
                HardcodedReferenceFinding(
                    HardcodedReferenceKind.RESOURCE_NAME,
                    "app/src/main/java/com/example/Contract.java",
                    6,
                    "com.example.app:layout/home",
                ),
                HardcodedReferenceFinding(
                    HardcodedReferenceKind.RESOURCE_NAME,
                    "app/src/main/java/com/example/Contract.java",
                    7,
                    "android:drawable/hero",
                ),
                HardcodedReferenceFinding(
                    HardcodedReferenceKind.RESOURCE_NAME,
                    "app/src/main/java/com/example/Contract.java",
                    8,
                    "com.other:layout/home",
                ),
            ),
            emptyList(),
        )
        val disabledOrExcluded = HardeningSourceAudit(emptyList(), emptyList(), emptyList(), emptyList())

        assertEquals(
            setOf(ResourceType.DRAWABLE to "hero", ResourceType.LAYOUT to "home"),
            scopedExternallyNamedResources(enabled, "com.example.namespace", "com.example.app"),
        )
        assertEquals(
            emptySet(),
            scopedExternallyNamedResources(disabledOrExcluded, "com.example.namespace", "com.example.app"),
        )
    }
}
