# Keep UniFFI / JNA bindings for budlum-mobile-core
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class uniffi.** { *; }
-keep class network.budlum.validator.core.** { *; }
