plugins {
    id("com.android.application")
}

android {
    namespace = "com.yongpingbone.secretmode"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.yongpingbone.secretmode"
        minSdk = 30
        targetSdk = 36
        versionCode = 1
        versionName = "0.0.1-m0"
        testInstrumentationRunner = "com.yongpingbone.secretmode.crypto.CryptoProbeInstrumentation"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation("com.google.android.gms:play-services-code-scanner:16.1.0")
    implementation("com.google.zxing:core:3.5.4")
}
