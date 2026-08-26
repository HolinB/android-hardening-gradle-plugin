# Android Hardening Gradle Plugin 1.2.0

[Chinese](README.md)

`com.holin.android.hardening` is a local binary Gradle plugin for Android application variants. Within explicitly
selected variants and explicitly declared code/resource ownership, it reuses R8 mappings, assigns stable owned names,
audits external contracts, rewrites and re-signs an AAB, builds a universal APK, and emits auditable mapping, semantic,
similarity, and device-acceptance evidence. It defaults to `enabled=false`; ordinary build graphs do not depend on a
Hardening task.

## Safety limits

- Only Android modules and production source sets declared by `ownership` are rewrite inputs. Dependencies, generated and test directories, and excluded package roots are not owned.
- Unresolved app reflection, string resource lookup, and hardcoded class/member/resource/route/URI/URL/file references fail closed. The plugin cannot safely rename an unresolved external, JNI, JavaScript, reflection, or serialization contract.
- Potential Bean fields, Gson model fields without explicit `@SerializedName`, Java Serializable classes, ObjectBox entities, JNI native methods, and `@JavascriptInterface` names are preserved and reported. The final DEX is checked again for potential Bean field-name preservation.
- Resource names may change, but v1 requires stable resource IDs. Externally named resources, notification icons, animations, NinePatch files, dependencies, and generated resources have safety exclusions.
- The plugin does not guarantee arbitrary anti-reverse-engineering or fuzzy-detector evasion. A similarity score describes only the plugin-defined owned AAB/APK structure and content; it is not a security rating, store-review outcome, or third-party detector result.
- The plugin does not upload, publish, or notify an external system. `hardeningRun<Variant>` is the only authorized device entry and installs/launches an APK. Never combine a Hardening task with an `upload`, `publish`, `install`, or `notify` task in one invocation.

## Minimum toolchain and prerequisites

- Gradle 8.10+
- AGP 8.8+
- JDK 17+
- Kotlin Android Plugin 2.3+
- Android SDK, Build Tools, Platform Tools, and the consumer project's own Gradle Wrapper

Meeting version floors is not sufficient by itself. At startup, an AGP public API capability probe checks that the
runtime AGP still exposes the required public variant, artifact, signing, and AAPT2 capabilities. A missing capability
fails the build; the plugin does not fall back to private APIs or infer compatibility from the version alone.

The portable ZIP does not bundle AGP or the Kotlin plugin/runtime; the consumer resolves its own compatible versions.
It does contain the Hardening implementation and marker, fixed runtime closure, `LICENSE`, `NOTICE`,
`THIRD_PARTY_LICENSES.txt`, `verification-metadata.xml`, and `SHA256SUMS`.

## Verify and prepare the Release ZIP

Obtain the ZIP and published SHA-256 from the same Release. Verify the outer archive before extraction; do not trust the
name alone.

```shell
shasum -a 256 -c hardening-gradle-plugin-1.2.0-portable-maven.zip.sha256
mkdir -p .local/hardening-1.2.0
unzip -q hardening-gradle-plugin-1.2.0-portable-maven.zip -d .local/hardening-1.2.0
(cd .local/hardening-1.2.0 && shasum -a 256 -c SHA256SUMS)
```

On Linux, use `sha256sum -c hardening-gradle-plugin-1.2.0-portable-maven.zip.sha256` for the outer ZIP and
`sha256sum -c SHA256SUMS` for the extracted content. In PowerShell, compare
`Get-FileHash .\hardening-gradle-plugin-1.2.0-portable-maven.zip -Algorithm SHA256` with the Release value. When Gradle
dependency verification is enabled, review and place the ZIP's `verification-metadata.xml` at
`gradle/verification-metadata.xml` in the consumer.

## CI and Release boundary

The push/pull-request workflow uses JDK 17, validates both Wrapper checksums, runs the environment, unit, full functional
TestKit, and Portable ZIP verification tasks, and forces two byte-for-byte identical Portable ZIP builds. The existing
binary consumer fixture resolves the extracted Maven publication without `includeBuild`. The separate manual/weekly
Offline TestKit workflow prepares the checksum-pinned Gradle/AGP/Kotlin/AAPT2 matrix online, then performs and compares
two verified offline rebuilds on the same host.

Both workflows use read-only repository permissions. Their ZIPs exist only in runner-local storage for comparison and
are discarded with the job; CI does not upload an artifact, publish a plugin/Maven repository, create a Release or tag,
install/run an app, or notify another system. After local review and explicit authorization, Release delivery remains a
manual command run outside Actions:

```shell
gh release upload v1.2.0 \
  build/distributions/hardening-gradle-plugin-1.2.0-portable-maven.zip \
  build/distributions/hardening-gradle-plugin-1.2.0-portable-maven.zip.sha256
```

## The `hardeningw` launcher

The launcher requires `--project-dir`, a `--` separator, and at least one argument for the consumer Wrapper. It validates
JDK/Wrapper/SDK prerequisites, downloads and checks the ZIP against the pinned Release SHA-256 and internal
`SHA256SUMS`, atomically installs a versioned cache, and injects
`-PhardeningPluginRepo=<cache>/1.2.0/repository`. When download is unavailable and it runs from this source repository,
it can fall back to the local `packagePortableHardeningPlugin` task.

POSIX:

```shell
./hardeningw --project-dir ./consumer -- \
  -PandroidHardening=true :mobile:hardeningBundleDemoQa
```

PowerShell:

```powershell
.\hardeningw.ps1 --project-dir .\consumer -- `
  -PandroidHardening=true :mobile:hardeningBundleDemoQa
```

Batch:

```bat
hardeningw.bat --project-dir .\consumer -- -PandroidHardening=true :mobile:hardeningBundleDemoQa
```

Use `./hardeningw --version` to print the launcher version. Set `HARDENING_CACHE_HOME` only when a non-default cache is
needed; otherwise it uses the Gradle user cache.

## Direct extracted-Maven consumption

The complete neutral example is in [`examples/multi-module-consumer`](examples/multi-module-consumer). Resolve the
Hardening plugin group only from the extracted local repository. AGP/Kotlin and application dependencies may still use
the consumer's normal repositories. Do not use `includeBuild`, and do not depend on unpublished remote Hardening
coordinates.

```kotlin
// settings.gradle.kts
pluginManagement {
    val hardeningRepository = providers.gradleProperty("hardeningPluginRepo").orNull
        ?: error("Pass -PhardeningPluginRepo=<extracted>/repository")
    repositories {
        exclusiveContent {
            forRepository {
                maven {
                    name = "ExtractedHardeningPlugin"
                    url = uri(hardeningRepository)
                }
            }
            filter {
                includeGroup("com.holin.android.hardening")
            }
        }
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
```

```kotlin
// Root build.gradle.kts
plugins {
    id("com.android.application") version "8.13.2" apply false
    id("org.jetbrains.kotlin.android") version "2.3.0" apply false
    id("com.holin.android.hardening") version "1.2.0" apply false
}
```

```kotlin
// Application module build.gradle.kts
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("com.holin.android.hardening")
}
```

Direct invocation:

```shell
./gradlew -PhardeningPluginRepo=.local/hardening-1.2.0/repository \
  -PandroidHardening=true :mobile:hardeningBundleDemoQa
```

## Full `androidHardening` Kotlin DSL

This block covers the complete v1 public surface. Replace paths, plugin declarations, and the migration descriptor with
real reviewed consumer inputs. v1 requires `legacyPlugins.verifyCompatibility=true`, a real baseline, and at least one
declared and actually applied legacy plugin; there is no greenfield bypass. Automatic state migration may be disabled,
but when enabled it requires a real captured descriptor rather than copied placeholder content.

```kotlin
androidHardening {
    enabled.set(providers.gradleProperty("androidHardening").map(String::toBoolean).orElse(false))
    projectKey.set("demo")

    variants {
        include("demoQa")
    }

    ownership {
        generatedPackagePrefixes.add("com.example.demo.generated")
        excludedPackagePrefixes.add("com.example.demo.external")

        module(":mobile") {
            sourceSets.addAll("main", "demo")
            manifestFiles.from(layout.projectDirectory.file("src/demo/AndroidManifest.xml"))
            webp {
                include("src/demoResources/res/drawable/**/*.webp")
                exclude("src/demoResources/res/drawable/no_rewrite/**/*.webp")
            }
        }
        module(":core") {
            sourceSets.add("main")
        }
        module(":media") {
            sourceSets.add("main")
        }

        hardcodedReferences {
            kinds.set(setOf(CLASS_NAME, MEMBER_NAME, RESOURCE_NAME, ROUTE, URI, URL, FILE_NAME))
            includeGlobs.set(listOf("src/**/*.kt", "src/**/*.java", "src/**/*.xml"))
            excludeGlobs.set(listOf("**/test/**", "**/androidTest/**"))
            failOnUnresolvedOwnedReference.set(true)
        }
    }

    rules {
        sourceFiles.from("proguard-rules.pro")
        preserveExactRules.from("hardening-preserve-exact.pro")
        additionalRules.from("hardening-additional.pro")
    }

    mapping {
        storeDirectory.set(rootProject.layout.projectDirectory.dir(".hardening/mappings"))
        reusePrevious.set(true)
        missingPolicy.set(RECREATE)
        keepHistory.set(true)
        quarantineInvalid.set(true)
        lockTimeoutSeconds.set(60)
    }

    reproducibility {
        fixedSeed.set(providers.gradleProperty("androidHardeningFixedSeed"))
    }

    naming {
        strategy.set(TYPED_PSEUDOWORDS)
        renamePackages.set(true)
        reuseAcrossBuilds.set(true)
    }

    code {
        engine.set(R8)
        preserveLineNumbers.set(true)
        sourceFileMode.set(PSEUDONYMIZE)
        stringFog.set(PRESERVE_CURRENT)
        diversification {
            mode.set(DEX)
            contentSalt.set(FRESH_PER_BUILD)
            minimumCoverage.set(0.50)
            minimumSimHashDistance.set(4)
            maximumGrowth.set(0.05)
            enforceMaximumGrowth.set(false)
        }
    }

    resources {
        mode.set(RENAME_AND_AUDIT)
        renameLayouts.set(true)
        renameDrawables.set(true)
        renameStyles.set(true)
        preserveResourceIds.set(true)
        reuseNamesAcrossBuilds.set(true)
        styleHashPolicy.set(RESOURCE_TABLE_ONLY)
        bitmapDiversification {
            safeOnly.set(true)
            minimumCoverage.set(0.90)
            minimumPHashDistance.set(11)
            minimumSsim.set(0.995)
        }
    }

    contracts {
        unresolvedAppReflection.set(FAIL_BUILD)
        unresolvedResourceLookup.set(FAIL_BUILD)
        externalNames.set(PRESERVE_AND_REPORT)
    }

    signing {
        reuseVariantSigningConfig.set(true)
    }

    benchmark {
        mode.set(REPORT_ONLY)
    }

    similarity {
        mode.set(OWNED_AAB_APK)
        baselineDirectory.set(rootProject.layout.projectDirectory.dir(".hardening/baselines"))
        minimumImprovementPoints.set(0.01)
        enforceRelativeImprovement.set(true)
        maximumOverallExclusive.set(75.0)
        enforceMaximumOverall.set(false)
        maximumAabGrowth.set(0.10)
        enforceMaximumAabGrowth.set(false)
    }

    deviceAcceptance {
        autoSelectSingleDevice.set(true)
        serial.set(providers.gradleProperty("androidHardeningDeviceSerial"))
        applicationId.set(providers.gradleProperty("androidHardeningApplicationId"))
        applicationIdFromVariant.set(true)
        launchActivity.set(providers.gradleProperty("androidHardeningLaunchActivity"))
        launchActivityFromManifest.set(true)
        stabilitySeconds.set(30)
    }

    legacyPlugins {
        mode.set(PRESERVE_UNMANAGED)
        verifyCompatibility.set(true)
        baselineFile.set(rootProject.layout.projectDirectory.file("legacy/legacy-plugin-baseline.json"))
        plugin("neutralLegacy") {
            pluginId.set("com.example.legacy")
            expectedVersion.set("1.0.0")
            configurationInputs.from(
                rootProject.layout.projectDirectory.file("gradle/libs.versions.toml"),
                layout.projectDirectory.file("build.gradle.kts"),
            )
            mappingPaths.from(layout.buildDirectory.file("outputs/mapping/demoQa/mapping.txt"))
        }
    }

    compatibility {
        autoMigrateLegacyState.set(true)
        migrationDescriptor.set(
            rootProject.layout.projectDirectory.file("hardening/portable-state-migration.json"),
        )
    }
}
```

When these three optional Gradle properties are absent, device selection, application ID resolution from the variant,
and launch Activity resolution from the manifest retain their automatic defaults. A supplied property overrides its
corresponding automatic resolution.

Source-set declaration order inside `ownership.module` is priority order, and every entry must be an existing Android
production source set. AGP public APIs resolve custom `res.srcDir` roots, while WebP globs remain module-relative.
Explicit `hardcodedReferences.includeGlobs` must match an auditable production file; a typo fails instead of silently
opening the scope.

## WebP and contract preservation

WebP rewriting is default-off. It is enabled only for an owned drawable WebP matched by a module's
`webp.include(...)` and not matched by `exclude(...)`; exclusion wins. Dependency/generated resources, externally named
resources, notification icons, animated WebP, non-drawables, unverified WebP, and images with no safe perturbation are
not rewritten. A candidate must preserve dimensions and every alpha sample, meet SSIM/pHash thresholds, and respect the
byte-growth policy.

R8 naming never treats compilation alone as contract safety. The audit preserves and reports
Gson/Bean/Serializable/ObjectBox/JNI/JavaScript contracts, resolves hardcoded references, and fails on unresolved owned
reflection or resource lookup. `preserveExactRules` is for reviewed rules that must remain byte-exact;
`additionalRules` supplies extra rules. Do not hide an unknown external contract with a broad keep rule.

## Generated task table (example variant `demoQa`)

Every `variants.include("...")` generates the same family. The task suffix for `demoQa` is `DemoQa`.

| Phase | Task | With `androidHardening=false` | Purpose/boundary |
|---|---|---|---|
| Prepare | `prepareHardeningDemoQa` | Direct request fails with the opt-in command | Locks and prepares mapping, registry, seed, and configuration identity |
| Audit | `auditHardeningDemoQa` | Direct request fails | Audits source, runtime dependencies, rules, external contracts, and legacy plugins |
| Verify | `verifyHardeningDemoQa` | Direct request fails | Verifies AAB, R8 mapping continuity, Bean fields, and Retrace |
| Archive | `archiveHardeningDemoQa` | Direct request fails | Atomically publishes state, AAB, and reports only after verification |
| AAB entry | `hardeningBundleDemoQa` | Fails and prints its exact `-PandroidHardening=true` command | Produces a signed, verified hardened AAB |
| APK entry | `hardeningAssembleDemoQa` | Fails and prints its exact opt-in command | Produces and verifies a signed universal APK |
| Baseline | `captureHardeningBaselineDemoQa` | Direct request fails | Captures immutable ordinary/hardened owned AAB/APK evidence; run explicitly before first compare |
| Compare | `compareHardeningDemoQa` | Direct request fails | Compares against the baseline and enforces relative improvement |
| External compare | `compareExternalHardeningDemoQa` | Direct request fails | Uses `-PandroidHardeningReferenceAab=reference/release.aab` for an external AAB |
| Benchmark | `benchmarkHardeningDemoQa` | Direct request fails | `REPORT_ONLY` lifecycle marker; no upload or device execution |
| Smoke | `smokeHardeningDemoQa` | Direct request fails; enabled direct device execution is also rejected | Device work can be authorized only by `hardeningRunDemoQa` |
| Run | `hardeningRunDemoQa` | Fails and prints its exact opt-in command | After compare, installs, launches, observes 30 seconds, then archives |
| Hardened APK | `assembleHardeningDemoQaUniversalApk` | Internal task is skipped | Builds, signs, zipaligns, and verifies a universal APK from the verified AAB |
| Ordinary APK | `assembleOrdinaryDemoQaUniversalApk` | Internal task is skipped | Builds the ordinary universal APK only for baseline/similarity |

Ordinary `assembleDemoQa` and `bundleDemoQa` never gain Hardening dependencies, whether the property is off or merely on
without a requested Hardening entry. Do not treat an ordinary APK/AAB as hardened. The plugin never calls an uploader;
perform upload in a separate, explicitly authorized consumer step after this invocation completes and the output is
verified.

## Outputs, reports, and state

For variant name `demoQa`, the path component remains `demoQa`:

- `build/outputs/hardening/<variant>/<variant>-hardened.aab`
- `build/outputs/hardening/<variant>/<variant>-hardened-universal.apk`
- `build/outputs/hardening/<variant>/<variant>-ordinary-universal.apk`
- `build/reports/hardening/<variant>/audit.json`
- `build/reports/hardening/<variant>/bundle-verification.json`
- `build/reports/hardening/<variant>/mapping-verification.json`
- `build/reports/hardening/<variant>/universal-apk-verification.json`
- `build/reports/hardening/<variant>/similarity-report.json` and `.md`
- `build/reports/hardening/<variant>/external-aab-similarity-report.json` and `.md`
- `build/hardening/<variant>/prepared-<invocation-id>/` and `build/hardening/<variant>/invocations/<invocation-id>/`
- `.hardening/mappings/<projectKey>/<variant>/current/`, `history/`, `quarantine/`, and `locks/`
- `.hardening/baselines/<projectKey>/<variant>/v1/`

On a first run with no old mapping, `missingPolicy=RECREATE` starts a new lineage at generation 0. With no history there is
no continuity to inherit, so the first build is not proof of cross-release stability. Later, `reusePrevious=true` supplies
the previous app-owned mapping as an R8 `-applymapping` input. Verification checks mapping continuity symbol by symbol and
uses the current official R8 Retrace to recover class, method, and line. With `quarantineInvalid=true`, corrupt or
identity-mismatched current state is isolated under a content hash; verified state is archived in immutable `history` by
AAB identity.

Before the first similarity comparison, explicitly run `captureHardeningBaselineDemoQa` on reviewed inputs. A baseline is
bound to ownership and complete configuration identity; a different configuration, variant, or input cannot impersonate
it. v1 enforces at least `minimumImprovementPoints` relative improvement. `maximumOverallExclusive` and
`maximumAabGrowth` are reported, but v1 requires their enforcement switches to remain `false`. The score does not prove
detector evasion.
Scores range from 0 to 100; lower means less similar under the plugin's owned-structure model. The relative gate requires
every measured dimension to fall by enough points rather than accepting an average-only improvement.

## Reproducibility, signing, and devices

The default uses a secure random invocation salt: stable mapping/registry state can be reused while AAB/APK payload bytes
rotate. Passing `-PandroidHardeningFixedSeed=<non-secret-lab-seed>` fixes derivation identity and permits deterministic
packages when source, toolchain, dependencies, signing material, configuration, path semantics, and state are all equal
across clean roots. A fixed seed is not a secret and cannot neutralize environmental/input differences; never treat a
test seed as a production secret or security control.

`signing.reuseVariantSigningConfig=true` reuses the selected variant's signing material. The plugin verifies certificate
and signature relationships across the hardened AAB, universal APK, and ordinary comparison APK. Neither this repository
nor the example ships a keystore or credentials. With no `deviceAcceptance.serial`, `hardeningRunDemoQa` auto-selects only
when exactly one online device exists; zero or multiple devices fail. It derives application ID and launch activity from
the variant/merged manifest, installs the APK, and observes it for 30 seconds.

## Offline preparation and use

Prepare the versioned plugin cache and all consumer dependencies in a controlled online environment, then disconnect:

```shell
./hardeningw --project-dir ./consumer -- \
  -PandroidHardening=true --offline :mobile:hardeningBundleDemoQa
```

The portable ZIP excludes AGP/Kotlin, so extracting it alone does not make the whole consumer build offline. For a fully
checksum-pinned matrix, use the published offline TestKit ZIP. It carries the supported matrix, Gradle distributions,
merged repositories, dependency-verification metadata, and per-file checksums. Do not let an offline run fall back to an
unknown host cache or network.

## Troubleshooting

- **Hardening disabled message:** pass exact `-PandroidHardening=true` and request `hardeningBundle<Variant>`, `hardeningAssemble<Variant>`, or `hardeningRun<Variant>`.
- **Plugin not found:** point `hardeningPluginRepo` at the extracted `repository`; ensure settings has no `includeBuild` or remote Hardening fallback.
- **Toolchain capability unavailable:** move to an AGP exposing the required public API. Do not bypass the probe or use private AGP classes.
- **Ownership/WebP include has no match:** check module-relative globs, custom source-set/resource roots, and real production files. Remove the include to retain default-off when no WebP is eligible.
- **Unresolved reflection/Gson/JNI/JavaScript:** make the reference statically resolvable, add an exact reviewed external-contract rule, or exclude a truly unowned package. Do not replace fail-closed behavior with guessed renaming.
- **Mapping continuity/Retrace failure:** preserve the report and `.hardening/mappings`, then inspect R8 version, prior mapping, configuration identity, and quarantine. Do not overwrite current/history manually.
- **Baseline missing or mismatched:** explicitly recapture from reviewed ordinary/hardened inputs. Never copy another project or variant's baseline.
- **Signing failure:** configure real signing for the selected variant; never commit credentials or a keystore.
- **Device selection failure:** connect exactly one authorized device or set `deviceAcceptance.serial`; enter device work only through `hardeningRun<Variant>`.
- **Similarity did not improve:** inspect owned-entry contributions and growth in JSON/Markdown. Threshold tuning is not proof of anti-reverse-engineering or detector evasion.
