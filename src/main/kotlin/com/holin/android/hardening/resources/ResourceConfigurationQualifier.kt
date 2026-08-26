package com.holin.android.hardening.resources

import com.android.aapt.ConfigurationOuterClass.Configuration

/** Converts an AAPT2 protobuf configuration to its canonical compiled resource-directory suffix. */
internal fun Configuration.toResourceQualifier(): String {
    require(product.isEmpty()) { "unsupported product-specific resources.pb configuration" }
    require(unknownFields.asMap().isEmpty()) { "unsupported fields in resources.pb configuration" }
    val parts = mutableListOf<String>()
    if (mcc != 0) parts += "mcc$mcc"
    if (mnc != 0) parts += "mnc$mnc"
    if (locale.isNotEmpty()) parts += localeQualifier(locale)
    enumPart(
        "grammatical gender",
        grammaticalGender,
        Configuration.GrammaticalGender.GRAM_GENDER_USET,
        mapOf(
            Configuration.GrammaticalGender.GRAM_GENDER_NEUTER to "neuter",
            Configuration.GrammaticalGender.GRAM_GENDER_FEMININE to "feminine",
            Configuration.GrammaticalGender.GRAM_GENDER_MASCULINE to "masculine",
        ),
    )?.let(parts::add)
    enumPart(
        "layout direction",
        layoutDirection,
        Configuration.LayoutDirection.LAYOUT_DIRECTION_UNSET,
        mapOf(
            Configuration.LayoutDirection.LAYOUT_DIRECTION_LTR to "ldltr",
            Configuration.LayoutDirection.LAYOUT_DIRECTION_RTL to "ldrtl",
        ),
    )?.let(parts::add)
    if (smallestScreenWidthDp != 0) parts += "sw${smallestScreenWidthDp}dp"
    if (screenWidthDp != 0) parts += "w${screenWidthDp}dp"
    if (screenHeightDp != 0) parts += "h${screenHeightDp}dp"
    enumPart(
        "screen layout size",
        screenLayoutSize,
        Configuration.ScreenLayoutSize.SCREEN_LAYOUT_SIZE_UNSET,
        mapOf(
            Configuration.ScreenLayoutSize.SCREEN_LAYOUT_SIZE_SMALL to "small",
            Configuration.ScreenLayoutSize.SCREEN_LAYOUT_SIZE_NORMAL to "normal",
            Configuration.ScreenLayoutSize.SCREEN_LAYOUT_SIZE_LARGE to "large",
            Configuration.ScreenLayoutSize.SCREEN_LAYOUT_SIZE_XLARGE to "xlarge",
        ),
    )?.let(parts::add)
    enumPart(
        "screen layout long",
        screenLayoutLong,
        Configuration.ScreenLayoutLong.SCREEN_LAYOUT_LONG_UNSET,
        mapOf(
            Configuration.ScreenLayoutLong.SCREEN_LAYOUT_LONG_LONG to "long",
            Configuration.ScreenLayoutLong.SCREEN_LAYOUT_LONG_NOTLONG to "notlong",
        ),
    )?.let(parts::add)
    enumPart(
        "screen round",
        screenRound,
        Configuration.ScreenRound.SCREEN_ROUND_UNSET,
        mapOf(
            Configuration.ScreenRound.SCREEN_ROUND_ROUND to "round",
            Configuration.ScreenRound.SCREEN_ROUND_NOTROUND to "notround",
        ),
    )?.let(parts::add)
    enumPart(
        "wide color gamut",
        wideColorGamut,
        Configuration.WideColorGamut.WIDE_COLOR_GAMUT_UNSET,
        mapOf(
            Configuration.WideColorGamut.WIDE_COLOR_GAMUT_WIDECG to "widecg",
            Configuration.WideColorGamut.WIDE_COLOR_GAMUT_NOWIDECG to "nowidecg",
        ),
    )?.let(parts::add)
    enumPart(
        "HDR",
        hdr,
        Configuration.Hdr.HDR_UNSET,
        mapOf(
            Configuration.Hdr.HDR_HIGHDR to "highdr",
            Configuration.Hdr.HDR_LOWDR to "lowdr",
        ),
    )?.let(parts::add)
    enumPart(
        "orientation",
        orientation,
        Configuration.Orientation.ORIENTATION_UNSET,
        mapOf(
            Configuration.Orientation.ORIENTATION_PORT to "port",
            Configuration.Orientation.ORIENTATION_LAND to "land",
            Configuration.Orientation.ORIENTATION_SQUARE to "square",
        ),
    )?.let(parts::add)
    enumPart(
        "UI mode type",
        uiModeType,
        Configuration.UiModeType.UI_MODE_TYPE_UNSET,
        mapOf(
            Configuration.UiModeType.UI_MODE_TYPE_DESK to "desk",
            Configuration.UiModeType.UI_MODE_TYPE_CAR to "car",
            Configuration.UiModeType.UI_MODE_TYPE_TELEVISION to "television",
            Configuration.UiModeType.UI_MODE_TYPE_APPLIANCE to "appliance",
            Configuration.UiModeType.UI_MODE_TYPE_WATCH to "watch",
            Configuration.UiModeType.UI_MODE_TYPE_VRHEADSET to "vrheadset",
        ),
    )?.let(parts::add)
    enumPart(
        "UI night mode",
        uiModeNight,
        Configuration.UiModeNight.UI_MODE_NIGHT_UNSET,
        mapOf(
            Configuration.UiModeNight.UI_MODE_NIGHT_NIGHT to "night",
            Configuration.UiModeNight.UI_MODE_NIGHT_NOTNIGHT to "notnight",
        ),
    )?.let(parts::add)
    if (density != 0) {
        parts += when (density) {
            120 -> "ldpi"
            160 -> "mdpi"
            213 -> "tvdpi"
            240 -> "hdpi"
            320 -> "xhdpi"
            480 -> "xxhdpi"
            640 -> "xxxhdpi"
            0xfffe -> "anydpi"
            0xffff -> "nodpi"
            else -> "${density}dpi"
        }
    }
    enumPart(
        "touchscreen",
        touchscreen,
        Configuration.Touchscreen.TOUCHSCREEN_UNSET,
        mapOf(
            Configuration.Touchscreen.TOUCHSCREEN_NOTOUCH to "notouch",
            Configuration.Touchscreen.TOUCHSCREEN_STYLUS to "stylus",
            Configuration.Touchscreen.TOUCHSCREEN_FINGER to "finger",
        ),
    )?.let(parts::add)
    enumPart(
        "keys hidden",
        keysHidden,
        Configuration.KeysHidden.KEYS_HIDDEN_UNSET,
        mapOf(
            Configuration.KeysHidden.KEYS_HIDDEN_KEYSEXPOSED to "keysexposed",
            Configuration.KeysHidden.KEYS_HIDDEN_KEYSHIDDEN to "keyshidden",
            Configuration.KeysHidden.KEYS_HIDDEN_KEYSSOFT to "keyssoft",
        ),
    )?.let(parts::add)
    enumPart(
        "keyboard",
        keyboard,
        Configuration.Keyboard.KEYBOARD_UNSET,
        mapOf(
            Configuration.Keyboard.KEYBOARD_NOKEYS to "nokeys",
            Configuration.Keyboard.KEYBOARD_QWERTY to "qwerty",
            Configuration.Keyboard.KEYBOARD_TWELVEKEY to "12key",
        ),
    )?.let(parts::add)
    enumPart(
        "navigation hidden",
        navHidden,
        Configuration.NavHidden.NAV_HIDDEN_UNSET,
        mapOf(
            Configuration.NavHidden.NAV_HIDDEN_NAVEXPOSED to "navexposed",
            Configuration.NavHidden.NAV_HIDDEN_NAVHIDDEN to "navhidden",
        ),
    )?.let(parts::add)
    enumPart(
        "navigation",
        navigation,
        Configuration.Navigation.NAVIGATION_UNSET,
        mapOf(
            Configuration.Navigation.NAVIGATION_NONAV to "nonav",
            Configuration.Navigation.NAVIGATION_DPAD to "dpad",
            Configuration.Navigation.NAVIGATION_TRACKBALL to "trackball",
            Configuration.Navigation.NAVIGATION_WHEEL to "wheel",
        ),
    )?.let(parts::add)
    require((screenWidth == 0) == (screenHeight == 0)) {
        "resources.pb screen pixel dimensions must specify both width and height"
    }
    if (screenWidth != 0) parts += "${screenWidth}x$screenHeight"
    val sdkMinor = AaptResourceEntryCompat.sdkVersionMinor(this)
    require(sdkVersion != 0 || sdkMinor == 0) {
        "resources.pb SDK minor version has no major version"
    }
    if (sdkVersion != 0) {
        parts += if (sdkMinor == 0) "v$sdkVersion" else "v$sdkVersion.$sdkMinor"
    }
    return parts.joinToString("-")
}

private fun localeQualifier(tag: String): String {
    require(BCP47_TAG.matches(tag)) { "invalid BCP-47 locale in resources.pb: $tag" }
    val subtags = tag.split('-')
    val language = subtags.first().lowercase()
    val scriptIndex = (1 until subtags.size).firstOrNull { index ->
        subtags[index].length == 4 && subtags[index].all(Char::isLetter)
    } ?: -1
    val regionIndex = (1 until subtags.size).firstOrNull { index ->
        val subtag = subtags[index]
        (subtag.length == 2 && subtag.all(Char::isLetter)) ||
            (subtag.length == 3 && subtag.all(Char::isDigit))
    } ?: -1
    val hasExtendedSubtags = scriptIndex >= 0 || subtags.indices.any { index ->
        index > 0 && index != regionIndex
    }
    if (!hasExtendedSubtags) {
        return if (regionIndex < 0) language else "$language-r${subtags[regionIndex].uppercase()}"
    }
    val canonical = subtags.mapIndexed { index, subtag ->
        when (index) {
            0 -> subtag.lowercase()
            scriptIndex -> subtag.lowercase().replaceFirstChar(Char::uppercase)
            regionIndex -> subtag.uppercase()
            else -> subtag
        }
    }
    return "b+" + canonical.joinToString("+")
}

private fun <T : Enum<T>> enumPart(
    field: String,
    value: T,
    unset: T,
    mappings: Map<T, String>,
): String? {
    if (value == unset) return null
    return requireNotNull(mappings[value]) { "unsupported $field value in resources.pb: $value" }
}

private val BCP47_TAG = Regex("[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*")
