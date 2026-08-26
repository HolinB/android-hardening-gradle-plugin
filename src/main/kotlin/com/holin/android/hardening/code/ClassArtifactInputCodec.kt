package com.holin.android.hardening.code

import java.nio.file.Path
import java.util.Base64

data class ClassArtifactInput(
    val component: String,
    val modulePath: String?,
    val file: Path,
    val hierarchyPrecedence: Int? = null,
) {
    init {
        require(hierarchyPrecedence == null || hierarchyPrecedence >= 0) {
            "class artifact hierarchy precedence must be non-negative"
        }
    }
}

object ClassArtifactInputCodec {
    fun encode(input: ClassArtifactInput): String = listOf(
        input.component,
        input.modulePath.orEmpty(),
        input.file.toAbsolutePath().normalize().toString(),
        input.hierarchyPrecedence?.toString().orEmpty(),
    ).joinToString(".") { field ->
        Base64.getUrlEncoder().withoutPadding().encodeToString(field.toByteArray(Charsets.UTF_8))
    }

    fun decode(value: String): ClassArtifactInput {
        val fields = value.split('.').map { field ->
            String(Base64.getUrlDecoder().decode(field), Charsets.UTF_8)
        }
        require(fields.size == FIELD_COUNT) { "invalid class artifact input" }
        val precedence = fields[3].ifEmpty { null }?.let { encoded ->
            requireNotNull(encoded.toIntOrNull()) { "invalid class artifact hierarchy precedence" }
        }
        return ClassArtifactInput(fields[0], fields[1].ifEmpty { null }, Path.of(fields[2]), precedence)
    }

    private const val FIELD_COUNT = 4
}
