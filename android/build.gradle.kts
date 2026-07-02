// Top-level build file. Plugin versions are declared here and applied
// per-module. Keep dependency declarations out of this file.
plugins {
    id("com.android.application") version "8.7.0" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21" apply false
    id("org.jetbrains.kotlin.plugin.serialization") version "2.0.21" apply false
    // KSP drives Room's annotation processor. The version is pinned to the
    // Kotlin release (2.0.21) — bump both together.
    id("com.google.devtools.ksp") version "2.0.21-1.0.28" apply false
}
