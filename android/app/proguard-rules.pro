# BouncyCastle is used directly (no JCA provider), so R8 can strip what we don't call.
-dontwarn org.bouncycastle.**
-dontwarn javax.naming.**
-dontwarn org.conscrypt.**
-dontwarn org.openjsse.**
