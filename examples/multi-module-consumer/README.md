# Neutral multi-module consumer

This configuration-only example has an Android application module `:mobile`, two owned Android library modules
`:core` and `:media`, and the package root `com.example.demo`. It intentionally contains no application code,
credentials, keystore, mapping, baseline, binary output, or production asset.

1. Extract `hardening-gradle-plugin-1.3.0-portable-maven.zip` and verify its `SHA256SUMS` first.
2. Point `-PhardeningPluginRepo` at the extracted `repository` directory.
3. Add your own production sources and owned images matched by the configured scopes. PNG demonstrates the new
   `images` DSL; WebP deliberately uses the legacy `webp` DSL to demonstrate 1.2.0 compatibility. Remove an include when
   no owned image is eligible; image diversification is default-off when there are no formats/includes.
4. Supply signing values through the four `DEMO_SIGNING_*` environment variables. The example never stores them.
5. Replace the neutral legacy declaration, apply that real plugin, and capture its real baseline. v1 requires
   `verifyCompatibility=true` and does not provide a greenfield bypass for a hardened invocation.
6. The example opts into omitting only AAB `dependencies.pb` and adding 16 AAB-only structure entries. Remove the
   `bundle` block to retain the 1.2.0-compatible defaults (`PRESERVE` and `0`).

Ordinary build (hardening stays off):

```shell
./gradlew -PhardeningPluginRepo=.local/hardening/repository :mobile:assembleDemoQa
```

Explicit hardened entry after completing the application inputs:

```shell
./gradlew -PhardeningPluginRepo=.local/hardening/repository \
  -PandroidHardening=true -PandroidHardeningFixedSeed=replace-for-reproducible-lab-only \
  :mobile:hardeningBundleDemoQa
```
