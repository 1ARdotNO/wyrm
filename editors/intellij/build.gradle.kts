// Build with a JDK 17+ and Gradle: `./gradlew buildPlugin`.
// NOTE: this scaffold was not compiled in the environment it was authored in
// (no JDK/Gradle); pin versions to your toolchain and verify the LSP4IJ API.
plugins {
    id("java")
    id("org.jetbrains.kotlin.jvm") version "2.4.20"
    id("org.jetbrains.intellij.platform") version "2.19.0"
}

group = "dev.wyrm"
version = "0.1.0"

repositories {
    mavenCentral()
    intellijPlatform {
        defaultRepositories()
    }
}

dependencies {
    intellijPlatform {
        intellijIdeaCommunity("2024.2")
        // LSP support for JetBrains IDEs.
        plugin("com.redhat.devtools.lsp4ij:0.7.0")
    }
}

intellijPlatform {
    pluginConfiguration {
        ideaVersion {
            sinceBuild = "242"
        }
    }
}

kotlin {
    jvmToolchain(17)
}
