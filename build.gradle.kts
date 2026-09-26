plugins {
    java
    id("com.gradleup.shadow") version "9.0.0"
}
group = "net.voidflame"
version = "1.0.0"
repositories {
    mavenCentral()
    maven("https://repo.papermc.io/repository/maven-public/")
    }
dependencies {
    compileOnly("io.papermc.paper:paper-api:26.2.build.+")
    compileOnly("net.voidflame:VoidFlame-Core:api")
}
java { toolchain.languageVersion.set(JavaLanguageVersion.of(25)); withSourcesJar() }
tasks.withType<JavaCompile>().configureEach { options.encoding="UTF-8"; options.release.set(25) }
tasks.jar { archiveBaseName.set(project.name) }
tasks.shadowJar { archiveBaseName.set(project.name); archiveClassifier.set("") }
tasks.build { dependsOn(tasks.shadowJar) }

// Core API source dependency is resolved from the movable `api` tag.

// CI refresh after Core database fix.
