package com.holin.android.hardening

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class HardeningImageScopeTest {
    @Test
    fun `image scope is opt in and exclusion wins`() {
        val scope = HardeningOwnership.ImageScope.resolve(
            listOf("src/main/res/drawable/**/*"),
            listOf("src/main/res/drawable/private/**"),
            listOf(ImageFormat.PNG, ImageFormat.JPEG),
        )

        assertTrue(scope.includes("src/main/res/drawable/icons/hero.png", ImageFormat.PNG))
        assertTrue(scope.includes("src/main/res/drawable/icons/hero.jpeg", ImageFormat.JPEG))
        assertFalse(scope.includes("src/main/res/drawable/icons/hero.webp", ImageFormat.WEBP))
        assertFalse(scope.includes("src/main/res/drawable/private/hero.png", ImageFormat.PNG))
        assertFalse(HardeningOwnership.ImageScope.none().includes("src/main/res/drawable/hero.png", ImageFormat.PNG))
    }

    @Test
    fun `image scope normalizes paths and formats`() {
        val scope = HardeningOwnership.ImageScope.resolve(
            listOf("./src//main/res/drawable/*.png"),
            emptyList(),
            listOf(ImageFormat.PNG),
        )

        assertEquals(setOf("src/main/res/drawable/*.png"), scope.includes)
        assertEquals(setOf(ImageFormat.PNG), scope.formats)
    }

    @Test
    fun `legacy webp exclusion does not exclude png`() {
        val module = HardeningOwnership.OwnedModule(
            ":app",
            java.nio.file.Path.of("/tmp/app"),
            setOf("main"),
            webp = HardeningOwnership.WebpScope.resolve(
                setOf("src/main/res/drawable/**"),
                setOf("src/main/res/drawable/private/**"),
            ),
            images = HardeningOwnership.ImageScope.resolve(
                setOf("src/main/res/drawable/**"),
                emptySet(),
                setOf(ImageFormat.PNG),
            ),
        )

        // The same glob is declared by both scopes, but each format keeps its own rules.
        assertTrue(module.images.includes("src/main/res/drawable/public/hero.png", ImageFormat.PNG))
        assertTrue(module.images.includes("src/main/res/drawable/public/hero.webp", ImageFormat.WEBP))
        assertFalse(module.images.includes("src/main/res/drawable/private/hero.webp", ImageFormat.WEBP))
        assertTrue(module.images.includes("src/main/res/drawable/private/hero.png", ImageFormat.PNG))
    }
}
