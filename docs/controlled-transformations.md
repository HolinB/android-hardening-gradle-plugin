# Controlled transformations introduced in 1.3.1–1.4.0

The existing transformation defaults remain compatible with 1.3.0. Each new policy is opt-in and participates in Gradle task inputs and the configuration identity. A requested minimum coverage is a build gate; skipped or ineffective conversions do not satisfy it.

| Version | Capability | Proof and applicability |
|---|---|---|
| 1.3.1 | Category report and derived debuggable APK | The original structural-v1 score is retained. A derived APK changes the debuggable flag and signature only; all other ZIP payloads are compared. |
| 1.3.2 | Value resource logical names | Resource IDs, configurations and values remain stable. Dynamic lookup, externally observed names and unresolved references preserve the original name. |
| 1.3.3 | Pixel-exact images | PNG, WebP and JPEG retain dimensions, decoded RGBA and rendering metadata. Six background composites are verified. Pixel pHash is allowed to remain identical. |
| 1.3.4 | Controlled assets | Actual source directories and byte matches establish ownership. Supported images, SFNT tables and JSON token streams have format-specific equivalence proofs. |
| 1.3.5 | Internal components | Private Java Activities with closed identities can be renamed within their package. A private legacy activity-alias preserves old explicit intents. External components, filters, unresolved Kotlin metadata and identity observations remain unchanged. |
| 1.3.6 | Runtime strings and asset containers | Tracked platform getString calls and explicitly named AssetManager.open readers are adapted before R8. AES-GCM envelopes are independently decoded and compared. Locale selection occurs before string decoding. |
| 1.3.7 | Native format and dependency provenance | Supported Android ELF files receive an nonloaded format trailer with an exact content check; original bytes and program-header/PT_LOAD fingerprints are checked. Whitelisted stateless Java utility libraries can receive closed class aliases before R8. |
| 1.3.8 | Integration and compatibility | Canonical mapping is checked against the compiler mapping with an inverse proof before compiler metadata is detached. Repeated resolved artifact records are deduplicated by actual source path. Owned ViewModel factory classes retain generic identities and constructors under R8, while their names may be obfuscated. |
| 1.4.0 | Final distribution | Source archives without Git metadata use an external temporary Git context for native ignore semantics. No consumer `.git` is created; damaged repositories still fail. The final release contains production implementation and pre-existing tests; temporary verification code is excluded from source and portable distributions. |

Example configuration using the 1.4.2 aliases (only include scopes verified for the consuming application):

```kotlin
androidHardening {
    verification { debuggableApkVariants.add("demoDebug") }
    resources {
        values {
            enabled.set(true)
            minimumCoverage.set(0.0)
        }
        bitmapDiversification {
            mode.set(com.holin.android.hardening.resources.BitmapMode.PIXEL_EXACT)
            minimumSsim.set(1.0)
            minimumPHashDistance.set(0)
        }
    }
    assetProtection {
        enabled.set(true)
        includes.add("owned/images/*.png")
        images.set(true)
        minimumCoverage.set(1.0)
    }
    componentProtection {
        enabled.set(true)
        includes.add("com.example.app.InternalActivity")
        minimumCoverage.set(1.0)
    }
    runtimeProtection {
        strings.add("internal_status")
        minimumStringCoverage.set(1.0)
        assetPaths.add("owned/settings.json")
        assetReaders.add("com/example/app/Reader#load(Landroid/content/res/AssetManager;)V")
        minimumAssetCoverage.set(1.0)
    }
    nativeProtection {
        enabled.set(true)
        includes.add("base/lib/*/*.so")
        minimumCoverage.set(1.0)
    }
    dependencyProtection {
        enabled.set(true)
        includes.add("com.example:pure-utility:1.0")
        minimumCoverage.set(1.0)
    }
}
```

An enabled dependencyProtection block with an empty allowlist produces provenance only. It does not relocate SDKs. The report records original artifact hashes, effective class artifact hashes and separate derived artifacts. Gradle's dependency cache is read-only to this implementation. Pure-utility eligibility excludes state, construction, serialization, native methods, service/resource/signature contracts, reflection, Kotlin metadata, type escapes and unsupported calls. R8 may remove or inline an eligible class; the final report does not count its pre-R8 alias as an effective surviving class rename without DEX evidence.

Runtime protection excludes unadapted string readers, rich text, plurals, arrays, aliases, unresolved resource lookup, unknown asset readers, Native and WebView asset access. Version 1.5.0 adapts packaged platform getters and selected owned asset open/list/descriptor calls, and adds opt-in XML drawable containers; see [runtime content protection](runtime-content-protection.md). A zero minimum allows an explicitly reported skip. A positive minimum fails when the requested scope cannot be proven closed. This policy does not weaken the existing resource or DEX semantic verifiers.

Native conversion changes the whole-file fingerprint only. It does not change machine code, loaded data, symbols, relocations, SONAME or build-id. Image conversion changes encoded bytes while visible content remains equal. JSON retains exact lexical tokens, including number spelling; SFNT conversion retains glyph and shaping tables. These distinctions are reported independently and do not predict a third-party similarity detector's result.

Hardening Debug is first compiled through the release processing chain: minification is enabled and compiler debuggability is disabled, while the original Debug BuildConfig switch is retained. The optional deriveHardening<Variant>DebuggableApk task then updates only the application debuggable flag, aligns and signs the APK with the configured key, and verifies payload identity. The formal Release output remains non-debuggable.

Reports live under build/reports/hardening/<variant>. Relevant files include category-report.json, controlled-transformations.json, components.json, component-classes.json, component-mapping.json, runtime-readers.json and dependencies.json. Canonical mappings reverse pre-R8 aliases for external Retrace. The compiler mapping remains detached from the final AAB, preserving the existing distribution contract.
