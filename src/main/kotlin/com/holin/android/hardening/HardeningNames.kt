package com.holin.android.hardening

object HardeningNames {
    private val projectKeyPattern = Regex("[a-z0-9][a-z0-9._-]*")
    private val variantPattern = Regex("[A-Za-z][A-Za-z0-9]*")

    fun requireProjectKey(value: String): String = requireMatch(projectKeyPattern, "projectKey", value)

    fun requireVariant(value: String): String = requireMatch(variantPattern, "variant", value)

    fun taskSuffix(variant: String): String = requireVariant(variant).replaceFirstChar(Char::uppercaseChar)

    private fun requireMatch(pattern: Regex, label: String, value: String): String {
        require(pattern.matches(value)) { "$label '$value' does not match ${pattern.pattern}" }
        return value
    }
}
