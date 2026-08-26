# Add reviewed application-specific R8 rules here. Keep this file credential-free.
-keepclassmembers class * {
    @com.google.gson.annotations.SerializedName <fields>;
}
