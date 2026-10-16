# Runtime content protection

The 1.5.0 local build reuses the existing authenticated resource envelope, reader adapter, ownership audit, stable resource IDs, mappings, signing, and independent artifact verification. `runtimeProtection.images` defaults to disabled. The existing runtime policy encoding is unchanged when images are disabled.

```kotlin
androidHardening {
    runtimeProtection {
        strings.add("internal_status")
        minimumStringCoverage.set(1.0)
        assetPaths.add("owned/emoji/smile.png")
        assetReaders.add("com/example/app/Reader#load(Landroid/content/Context;Ljava/lang/String;)Landroid/graphics/Bitmap;")
        minimumAssetCoverage.set(1.0)
        images {
            enabled.set(true)
            includes.set(setOf("drawable/owned_hero"))
            minimumCoverage.set(1.0)
        }
    }
}
```

Resource string analysis resolves final inline IDs using the current variant's R classes, inherited platform getters, and packaged forwarding calls. Known dynamic resource names/types narrow exclusions. Unsupported consumers, XML references, aliases, rich text, arrays and plurals remain subject to exclusion. A nonzero minimum fails a build whose selected scope is not closed. Audit the final transformed resource table as well as the reader report.

Asset adapters support `open` access modes, directory `list`, and seekable descriptors for the selected owned assets. The Application bootstrap stores a context; a descriptor request lazily decrypts into a private temporary file, opens it, then unlinks it. Encryption uses the original bytes. A selected encrypted asset does not also undergo image format conversion. The build's content salt participates directly in the authenticated envelope's nonce derivation, so identical input and salt reproduce output while a new salt changes ciphertext.

The initial image contract is PNG/WebP loaded through ordinary XML drawable inflation on API 26 or newer. The compiled file becomes a custom Drawable XML resource containing authenticated encrypted payload chunks. Resource IDs, configuration selection and source density are preserved. Each inflation creates its own mutable Drawable state; a bounded cache shares only immutable bitmap pixels. The adapter delegates bounds, alpha, tint, state, visibility, level, callbacks and constant-state recreation.

Direct bytecode image readers, bitmap-specific custom Views, unsupported XML consumers, missing naming/symbol closure, system and externally named resources, Manifest/theme/value references, NinePatch and animations are preserved and reported. This feature does not adapt arbitrary `BitmapFactory`, Native, WebView, remote-process or raw-file readers. Declare narrow owned scopes and validate the actual consuming application's pages before deployment.

`runtime-readers.json` records the reader audit. `controlled-transformations.json` records encrypted images, selected/transformed entry counts, original/protected bytes and separate count/byte coverage. Encoding and encryption are mutually exclusive per payload and have separate counters. The semantic verifier authenticates and recovers the exact original image/asset bytes, checks custom XML structure and normalizes only the declared table file-type changes before the existing independent resource comparison.

Encryption removes directly extractable payloads from the selected static resource entries; the application necessarily includes decoding capability. Residual copies and unselected third-party content must be measured separately. Pixel/layout equality, a changed file hash, appended bytes or a lower aggregate similarity score alone do not establish additional content protection. No additional layout/style reorganization, Manifest relocation scheme or Native metadata stripping is introduced by this release.

The compiler mapping rules preserve interfaces extending `android.os.IInterface`. R8 may inline an SDK's Binder call into an owned class, where existing class-string adaptation would otherwise rewrite its protocol descriptor. Preserving the interface type prevents this protocol mismatch without retaining entire SDK packages or implementation methods. The ownership classifier uses the same compatibility rule, and the rule is kept outside the user-rule configuration fingerprint so existing mapping lineage remains reusable. Samsung verification exposed this problem in the original 1.4.2 Maps dialogs as well as the intermediate builds; the corrected build must be validated through both map dialogs.
