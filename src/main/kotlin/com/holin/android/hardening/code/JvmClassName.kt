package com.holin.android.hardening.code

internal object JvmClassName {
    fun isUnqualified(value: String): Boolean =
        value.isNotEmpty() && value.none { character -> character in FORBIDDEN_UNQUALIFIED_CHARACTERS }

    fun isInternal(value: String): Boolean = isSeparated(value, '/')

    fun isDotted(value: String): Boolean = isSeparated(value, '.')

    private fun isSeparated(value: String, separator: Char): Boolean {
        if (value.isEmpty()) return false
        var start = 0
        while (true) {
            val end = value.indexOf(separator, start)
            val segment = value.substring(start, if (end >= 0) end else value.length)
            if (!isUnqualified(segment)) return false
            if (end < 0) return true
            start = end + 1
        }
    }

    private val FORBIDDEN_UNQUALIFIED_CHARACTERS = setOf('.', ';', '[', '/')
}
