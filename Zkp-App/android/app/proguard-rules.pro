# ============================================================
# ZKP Identity App — ProGuard Rules
# ============================================================

# ─── Rust JNI — Main Bridge Classes ─────────────────────────
-keep class com.example.zkpapp.SecureVaultJni { *; }
-keep class com.example.zkpapp.ZkpJni { *; }
-keep class com.example.zkpapp.ProofBenchmarkResult { *; }

# ─── Rust JNI — external fun wali classes ───────────────────
-keep class com.example.zkpapp.SecurityGate { *; }
-keep class com.example.zkpapp.ZkAuth { *; }
-keep class com.example.zkpapp.VerifierActivity { *; }
-keep class com.example.zkpapp.OfflineMenuActivity { *; }

# ─── App Core Classes ────────────────────────────────────────
-keep class com.example.zkpapp.AuthViewModel { *; }
-keep class com.example.zkpapp.AuthUiState { *; }
-keep class com.example.zkpapp.ZkpApplication { *; }
-keep class com.example.zkpapp.MainActivity { *; }
-keep class com.example.zkpapp.AuthActivity { *; }
-keep class com.example.zkpapp.LoginActivity { *; }
-keep class com.example.zkpapp.TestProofActivity { *; }
-keep class com.example.zkpapp.ZkAuthManager { *; }

# ─── Most important: koi bhi external fun rename na ho ───────
-keepclasseswithmembernames class * {
    native <methods>;
}
-keepclasseswithmembers class * {
    private external <methods>;
    external <methods>;
}

# ─── JMRTD — NFC Passport Reading ───────────────────────────
-keep class org.jmrtd.** { *; }
-keep class net.sf.scuba.** { *; }
-dontwarn org.jmrtd.**
-dontwarn net.sf.scuba.**

# ─── SpongyCastle — Crypto ───────────────────────────────────
-keep class org.spongycastle.** { *; }
-dontwarn org.spongycastle.**

# ─── Kotlin Serialization ────────────────────────────────────
-keep class kotlinx.serialization.** { *; }
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt
-keepclassmembers class kotlinx.serialization.json.** { *** Companion; }

# ─── Retrofit + OkHttp ───────────────────────────────────────
-keep class retrofit2.** { *; }
-keep class okhttp3.** { *; }
-dontwarn retrofit2.**
-dontwarn okhttp3.**
-dontwarn okio.**

# ─── Kotlin Coroutines ───────────────────────────────────────
-keep class kotlinx.coroutines.** { *; }
-dontwarn kotlinx.coroutines.**

# ─── Jetpack Compose ─────────────────────────────────────────
-keep class androidx.compose.** { *; }
-dontwarn androidx.compose.**

# ─── Biometric ───────────────────────────────────────────────
-keep class androidx.biometric.** { *; }

# ─── General Android ─────────────────────────────────────────
-keepattributes SourceFile, LineNumberTable
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends androidx.lifecycle.ViewModel
