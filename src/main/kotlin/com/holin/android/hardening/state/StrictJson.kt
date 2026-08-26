package com.holin.android.hardening.state

internal object StrictJson {
    fun validate(json: String) = Parser(json, allowDecimalNumbers = false).validate()

    fun validateDocument(json: String) = Parser(json, allowDecimalNumbers = true).validate()

    private class Parser(
        private val input: String,
        private val allowDecimalNumbers: Boolean,
    ) {
        private var index = 0

        fun validate() {
            skipWhitespace()
            parseValue()
            skipWhitespace()
            require(index == input.length) { "unexpected JSON content at offset $index" }
        }

        private fun parseValue() {
            require(index < input.length) { "unexpected end of JSON" }
            when (input[index]) {
                '{' -> parseObject()
                '[' -> parseArray()
                '"' -> parseString()
                't' -> literal("true")
                'f' -> literal("false")
                'n' -> literal("null")
                '-', in '0'..'9' -> parseNumber()
                else -> throw IllegalArgumentException("invalid JSON value at offset $index")
            }
        }

        private fun parseObject() {
            index++
            skipWhitespace()
            val keys = mutableSetOf<String>()
            if (consume('}')) return
            while (true) {
                require(peek() == '"') { "JSON object key must be a string at offset $index" }
                val key = parseString()
                require(keys.add(key)) { "duplicate JSON object key: $key" }
                skipWhitespace()
                require(consume(':')) { "missing ':' after JSON object key at offset $index" }
                skipWhitespace()
                parseValue()
                skipWhitespace()
                if (consume('}')) return
                require(consume(',')) { "missing ',' in JSON object at offset $index" }
                skipWhitespace()
            }
        }

        private fun parseArray() {
            index++
            skipWhitespace()
            if (consume(']')) return
            while (true) {
                parseValue()
                skipWhitespace()
                if (consume(']')) return
                require(consume(',')) { "missing ',' in JSON array at offset $index" }
                skipWhitespace()
            }
        }

        private fun parseString(): String {
            require(consume('"')) { "JSON string must start with a quote at offset $index" }
            val result = StringBuilder()
            while (index < input.length) {
                val character = input[index++]
                when {
                    character == '"' -> return result.toString()
                    character == '\\' -> {
                        require(index < input.length) { "unterminated JSON escape" }
                        when (val escaped = input[index++]) {
                            '"', '\\', '/' -> result.append(escaped)
                            'b' -> result.append('\b')
                            'f' -> result.append('\u000c')
                            'n' -> result.append('\n')
                            'r' -> result.append('\r')
                            't' -> result.append('\t')
                            'u' -> {
                                require(index + 4 <= input.length) { "incomplete JSON unicode escape" }
                                val digits = input.substring(index, index + 4)
                                val code = digits.toIntOrNull(16)
                                    ?: throw IllegalArgumentException("invalid JSON unicode escape: $digits")
                                result.append(code.toChar())
                                index += 4
                            }
                            else -> throw IllegalArgumentException("invalid JSON escape: \\$escaped")
                        }
                    }
                    character.code < 0x20 -> throw IllegalArgumentException("unescaped control character in JSON string")
                    else -> result.append(character)
                }
            }
            throw IllegalArgumentException("unterminated JSON string")
        }

        private fun parseNumber() {
            val start = index
            if (peek() == '-') index++
            require(index < input.length && input[index].isDigit()) { "invalid JSON number at offset $start" }
            if (input[index] == '0') {
                index++
                require(index >= input.length || !input[index].isDigit()) { "leading zero in JSON number at offset $start" }
            } else {
                require(input[index] in '1'..'9') { "invalid JSON number at offset $start" }
                while (index < input.length && input[index].isDigit()) index++
            }
            if (allowDecimalNumbers && consume('.')) {
                require(index < input.length && input[index].isDigit()) {
                    "JSON fraction must contain a digit at offset $start"
                }
                while (index < input.length && input[index].isDigit()) index++
            }
            if (allowDecimalNumbers && (peek() == 'e' || peek() == 'E')) {
                index++
                if (peek() == '+' || peek() == '-') index++
                require(index < input.length && input[index].isDigit()) {
                    "JSON exponent must contain a digit at offset $start"
                }
                while (index < input.length && input[index].isDigit()) index++
            }
            require(allowDecimalNumbers || index >= input.length || input[index] !in charArrayOf('.', 'e', 'E')) {
                "JSON state numbers must be integers at offset $start"
            }
            val token = input.substring(start, index)
            if (!allowDecimalNumbers) {
                require(token.toLongOrNull() != null) { "JSON integer is outside signed 64-bit range: $token" }
            }
        }

        private fun literal(expected: String) {
            require(input.regionMatches(index, expected, 0, expected.length)) { "invalid JSON literal at offset $index" }
            index += expected.length
        }

        private fun skipWhitespace() {
            while (index < input.length && input[index] in charArrayOf(' ', '\n', '\r', '\t')) index++
        }

        private fun consume(expected: Char): Boolean = if (peek() == expected) {
            index++
            true
        } else {
            false
        }

        private fun peek(): Char? = input.getOrNull(index)
    }
}
