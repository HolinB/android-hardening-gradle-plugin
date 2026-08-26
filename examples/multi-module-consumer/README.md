# Neutral multi-module consumer

This configuration-only example has an Android application module `:mobile`, two owned Android library modules
`:core` and `:media`, and the package root `com.example.demo`. It intentionally contains no application code,
credentials, keystore, mapping, baseline, binary output, or production asset.

1. Extract `hardening-gradle-plugin-1.2.0-portable-maven.zip` and verify its `SHA256SUMS` first.
2. Point `-PhardeningPluginRepo` at the extracted `repository` directory.
3. Add your own production sources and any WebP matched by the configured include. Remove that include when no owned
   WebP is eligible; WebP diversification is default-off when there are no includes.
4. Supply signing values through the four `DEMO_SIGNING_*` environment variables. The example never stores them.
5. Replace the neutral legacy declaration, apply that real plugin, and capture its real baseline. v1 requires
   `verifyCompatibility=true` and does not provide a greenfield bypass for a hardened invocation.

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
