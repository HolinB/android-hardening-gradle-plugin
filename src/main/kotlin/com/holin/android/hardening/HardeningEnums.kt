package com.holin.android.hardening

enum class MissingPolicy { RECREATE }
enum class NamingStrategy { TYPED_PSEUDOWORDS }
enum class CodeEngine { R8 }
enum class SourceFileMode { PSEUDONYMIZE }
enum class StringFogMode { PRESERVE_CURRENT }
enum class DiversificationMode { DEX }
enum class ContentSaltMode { FRESH_PER_BUILD }
enum class ResourceMode { RENAME_AND_AUDIT }
enum class StyleHashPolicy { RESOURCE_TABLE_ONLY }
enum class UnresolvedContractPolicy { FAIL_BUILD }
enum class ExternalNamesMode { PRESERVE_AND_REPORT }
enum class BenchmarkMode { REPORT_ONLY }
enum class SimilarityMode { OWNED_AAB_APK }
enum class LegacyPluginMode { PRESERVE_UNMANAGED }
enum class HardcodedReferenceKind { CLASS_NAME, MEMBER_NAME, RESOURCE_NAME, ROUTE, URI, URL, FILE_NAME }
