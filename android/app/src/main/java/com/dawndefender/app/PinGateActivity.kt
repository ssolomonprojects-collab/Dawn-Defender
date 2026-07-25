package com.dawndefender.app

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.FileProvider
import java.io.File

class PinGateActivity : AppCompatActivity() {

    private val REQUIRED_PIN = "1234"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate()
        // In full layout: setContentView(R.layout.activity_pin_gate)
    }

    fun onVerifyPinClicked(enteredPin: String, apkPath: String) {
        if (enteredPin == REQUIRED_PIN) {
            Toast.makeText(this, "PIN Verified! Launching Android Package Installer...", Toast.LENGTH_SHORT).show()
            launchRealAndroidInstaller(apkPath)
            finish()
        } else {
            Toast.makeText(this, "Incorrect Security PIN! Access Denied.", Toast.LENGTH_LONG).show()
        }
    }

    private fun launchRealAndroidInstaller(apkPath: String) {
        val file = File(apkPath)
        if (!file.exists()) return

        val apkUri: Uri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
        } else {
            Uri.fromFile(file)
        }

        val installIntent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(apkUri, "application/vnd.android.package-archive")
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION
        }
        startActivity(installIntent)
    }
}
