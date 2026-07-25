package com.dawndefender.app

import android.content.Context
import android.content.pm.PackageManager

data class ApkInspectionResult(
    val packageName: String,
    val versionName: String,
    val riskScore: Int,
    val verdict: String,
    val redFlags: List<String>
)

object ApkInspector {

    private val DANGEROUS_PERMISSIONS = mapOf(
        "android.permission.REQUEST_INSTALL_PACKAGES" to "Requests ability to silently install unknown APK apps (Risk: +35)",
        "android.permission.INSTALL_PACKAGES" to "Silently installs packages without user prompt (Risk: +40)",
        "android.permission.BIND_ACCESSIBILITY_SERVICE" to "Accessibility Service access - can hijack screen & touch events (Risk: +45)",
        "android.permission.SYSTEM_ALERT_WINDOW" to "Overlay permission - can draw fake banking popups over real apps (Risk: +35)",
        "android.permission.RECEIVE_BOOT_COMPLETED" to "Autostarts background service on device reboot (Risk: +20)",
        "android.permission.READ_SMS" to "Reads private SMS & OTP verification codes (Risk: +30)",
        "android.permission.SEND_SMS" to "Can send premium rate SMS text messages (Risk: +35)",
        "android.permission.RECEIVE_SMS" to "Intercepts incoming SMS notifications & OTPs (Risk: +30)"
    )

    fun inspectApk(context: Context, apkPath: String): ApkInspectionResult {
        val pm = context.packageManager
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNATURES
        val pkgInfo = pm.getPackageArchiveInfo(apkPath, flags)

        if (pkgInfo == null) {
            return ApkInspectionResult(
                packageName = "Unknown",
                versionName = "0.0",
                riskScore = 90,
                verdict = "DANGEROUS",
                redFlags = listOf("Invalid or corrupt APK file package")
            )
        }

        val redFlags = mutableListOf<String>()
        var score = 0

        // Check Permissions
        pkgInfo.requestedPermissions?.forEach { perm ->
            DANGEROUS_PERMISSIONS[perm]?.let { flag ->
                redFlags.add(flag)
                score += 25
            }
        }

        // Check Signatures
        @Suppress("DEPRECATION")
        if (pkgInfo.signatures == null || pkgInfo.signatures.isEmpty()) {
            redFlags.add("Unsigned APK: Missing cryptographic developer certificate")
            score += 40
        }

        val finalScore = score.coerceIn(0, 100)
        val verdict = when {
            finalScore >= 60 -> "DANGEROUS"
            finalScore >= 20 -> "SUSPICIOUS"
            else -> "SAFE"
        }

        return ApkInspectionResult(
            packageName = pkgInfo.packageName ?: "Unknown Package",
            versionName = pkgInfo.versionName ?: "1.0",
            riskScore = finalScore,
            verdict = verdict,
            redFlags = if (redFlags.isEmpty()) listOf("No high-risk permissions detected") else redFlags
        )
    }
}
