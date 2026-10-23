# Runtime content protection

The 1.5.2 local build reuses the existing authenticated resource envelope, reader adapter, ownership audit, stable resource IDs, mappings, signing, and independent artifact verification. `runtimeProtection.images` defaults to disabled. Legacy runtime policy encoding remains unchanged when the new string groups and TextView adaptation are unused.

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

## String groups and migration

```kotlin
androidHardening {
    runtimeProtection {
        strings.add("existing_contract")
        minimumStringCoverage.set(1.0)
        requiredStrings.add("internal_message")
        candidateStrings.add("optional_status")
        excludedStrings.put("public_title", "Read by layout XML")
        adaptTextViewResourceSetters.set(false)
    }
}
```

All four groups must be disjoint. Conflicts list the resource names and fail validation; exclusion reasons must be nonblank. `strings` retains its original denominator and `minimumStringCoverage` gate. Every `requiredStrings` entry must pass both reader analysis and final encryption. `candidateStrings` failures preserve the original resource values, contribute to their own coverage denominator and produce an aggregate warning. `excludedStrings` are always reported. Removing an unsupported candidate from the encryption input does not turn its configured coverage into 100%.

New collections default to empty and setter adaptation defaults to false. Existing policies keep schema 1 and the same configuration encoding/fingerprint. Using the new fields produces schema 2, including every new field in configuration identity and task inputs; the decoder accepts both versions. Changing groups is an explicit configuration/mapping-lineage change. No consuming application's list or source code is migrated automatically. Start by inspecting the reports, then deliberately move optional UI entries to candidates or document exclusions; do not lower the old coverage gate to conceal an unsupported required entry.

## Independent preflight

```shell
./gradlew :app:checkHardeningDemoReleaseRuntimeStrings
```

The task is registered for variants selected by `androidHardening.variants`, including ordinary builds without `-PandroidHardening=true`. It compiles the current variant and reads original scoped classes, R symbols, available resource XML and the merged Manifest. It does not create a Bridge, encrypt resources, invoke R8, rewrite/sign an AAB or commit mapping state. Run it in a separate invocation from Hardening for the same variant, including the `assembleDemoReleaseHardening` and `bundleDemoReleaseHardening` wrappers. Explicit requests and indirect task-graph combinations are rejected. AGP's `toGet(CLASSES)` observes final artifacts; the preflight is deliberately not wired to a Hardening transformation chain.

The task applies legacy and required reader gates; candidates only warn. A pass covers the available preliminary inputs. Ownership, missing/removed resources, compiled XML/aliases and *all* final resource configurations are checked again against the AAB. Full Hardening runs the shared reader analyzer automatically; running preflight first is optional.

## Reader support and boundaries

Analysis resolves inline IDs using current-variant R symbols, inherited platform `getString`/`getText`, and packaged forwarding methods. It tracks allocation identities, alias contents and fixed-point summaries through fields, arguments and return values. Supported paths include local `int[]`/`IntArray`, boxed integer arrays, Kotlin `listOf`/`mutableListOf`/`arrayListOf`, Java `Arrays.asList`/`ArrayList`, array loads/stores, list `add`/`set`/`get`, iteration, boxing/unboxing, array `clone`, `Arrays.copyOf` and `System.arraycopy`. Standard operations require modeled JVM signatures and provable origins; this is not support for arbitrary collection implementations. Unknown operations, reflection, Native calls or unproven external escapes still disqualify all affected IDs. A safe getter and an unsupported consumer of the same resource exclude that resource as a whole.

XML, theme and resource-alias consumers remain unsupported; there is no XML decryption hook. XML parsing ignores comments and tools-only attributes and records actual reference locations. Rich text, resource arrays/plurals and unsupported values in any language/configuration remain unencrypted. Resource ID containers in code are distinct from Android string-array resources.

Set `adaptTextViewResourceSetters` to true only after accepting the system metadata difference. The adapter recognizes the platform final `setText(int)` and `setText(int, BufferType)` through TextView, Button, EditText, AppCompat and packaged custom subclasses when their hierarchy proves resolution. Protected values use the corresponding CharSequence setter once, preserving the current resource configuration, BufferType and error propagation. Ordinary values fall back to the original resource-ID overload (with an extra resource lookup used for detection). There is no ciphertext-first double setter, hidden API, reflection into internal fields or global Resources replacement. Protected calls may change resource-origin, autofill sensitivity and content-capture text-ID metadata; this difference is recorded in the report. With the switch off, those resource setters remain unsupported consumers.

Recognizing a setter does not establish that every reader of that resource is supported. The complete packaged dependency graph is analyzed too. For example, a dynamic `getIdentifier` path in AndroidX may carry a possible selected ID into an unmodeled consumer; the resource remains unprotected even when its AppCompat setter is recognized. Use the reported method locations to resolve the path, or explicitly place the resource in `candidateStrings` or `excludedStrings` according to the intended policy. The switch does not waive reader coverage.

## Diagnostic reports

Reports live under `build/reports/hardening/<variant>/`:

| File | Stage and meaning |
| --- | --- |
| `runtime-strings-preflight.json` | Preliminary original-class analysis; final resource checks remain pending |
| `runtime-readers.json` | Production reader analysis, written before reader coverage gates; `stringAnalysis` contains the complete string ledger |
| `runtime-strings-final.json` | Final AAB resource qualification and actual encryption counts, written before string eligibility/coverage errors are raised |

Each ledger contains all configured entries, including ownership failures, missing resources, explicit exclusions and reader failures. Entries are sorted by resource identity and include group, stage, status, reason codes, remediation and reader/reference locations. Code locations include class, method, JVM descriptor and source line when available, with instruction position otherwise. `NO_TRACEABLE_PLATFORM_GETSTRING` has no fabricated method location. Reports include variant and input fingerprint, group configured/reader-closed/eligible/transformed/excluded counts and original-denominator coverage. `PENDING_FINAL_RESOURCE_CHECK` and `ELIGIBLE_PENDING_TRANSFORM` are not evidence of encryption. Actual `TRANSFORMED` entries and `resourceTableInverseProof` are recorded only after the resource-table round trip succeeds; `finalArtifactVerified` remains false until the separate bundle semantic verification. Failure exceptions show counts, representative reasons and report paths. Reports do not contain resource plaintext or decryption keys.

The existing inverse bytecode proof and independent resource-table recovery checks remain mandatory. Inspect both reader and final reports; build results do not establish acceptance of a consuming application's pages.

Asset adapters support `open` access modes, directory `list`, and seekable descriptors for the selected owned assets. The Application bootstrap stores a context; a descriptor request lazily decrypts into a private temporary file, opens it, then unlinks it. Encryption uses the original bytes. A selected encrypted asset does not also undergo image format conversion. The build's content salt participates directly in the authenticated envelope's nonce derivation, so identical input and salt reproduce output while a new salt changes ciphertext.

The initial image contract is PNG/WebP loaded through ordinary XML drawable inflation on API 26 or newer. The compiled file becomes a custom Drawable XML resource containing authenticated encrypted payload chunks. Resource IDs, configuration selection and source density are preserved. Each inflation creates its own mutable Drawable state; a bounded cache shares only immutable bitmap pixels. The adapter delegates bounds, alpha, tint, state, visibility, level, callbacks and constant-state recreation.

Direct bytecode image readers, bitmap-specific custom Views, unsupported XML consumers, missing naming/symbol closure, system and externally named resources, Manifest/theme/value references, NinePatch and animations are preserved and reported. This feature does not adapt arbitrary `BitmapFactory`, Native, WebView, remote-process or raw-file readers. Declare narrow owned scopes and validate the actual consuming application's pages before deployment.

`runtime-readers.json` records the reader audit. `controlled-transformations.json` records encrypted images, selected/transformed entry counts, original/protected bytes and separate count/byte coverage. Encoding and encryption are mutually exclusive per payload and have separate counters. The semantic verifier authenticates and recovers the exact original image/asset bytes, checks custom XML structure and normalizes only the declared table file-type changes before the existing independent resource comparison.

Encryption removes directly extractable payloads from the selected static resource entries; the application necessarily includes decoding capability. Residual copies and unselected third-party content must be measured separately. Pixel/layout equality, a changed file hash, appended bytes or a lower aggregate similarity score alone do not establish additional content protection. No additional layout/style reorganization, Manifest relocation scheme or Native metadata stripping is introduced by this release.

The compiler mapping rules preserve interfaces extending `android.os.IInterface`. R8 may inline an SDK's Binder call into an owned class, where existing class-string adaptation would otherwise rewrite its protocol descriptor. Preserving the interface type prevents this protocol mismatch without retaining entire SDK packages or implementation methods. The ownership classifier uses the same compatibility rule, and the rule is kept outside the user-rule configuration fingerprint so existing mapping lineage remains reusable. Samsung verification exposed this problem in the original 1.4.2 Maps dialogs as well as the intermediate builds; the corrected build must be validated through both map dialogs.
