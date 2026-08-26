plugins {
    id("com.android.application")
}

android {
    namespace = "com.yongpingbone.secretmode"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.yongpingbone.secretmode"
        minSdk = 30
        targetSdk = 37
        versionCode = 1
        versionName = "0.0.1-m0"
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
