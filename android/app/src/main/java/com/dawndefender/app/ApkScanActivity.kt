package com.dawndefender.app

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class ApkScanActivity : AppCompatActivity() {

    private var apkPath: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate()
        // In full layout: setContentView(R.layout.activity_apk_scan)

        apkPath = intent.getStringExtra("APK_PATH")
        val fileName = intent.getStringExtra("FILE_NAME") ?: "Downloaded APK"

        if (apkPath != null) {
            val result = ApkInspector.inspectApk(this, apkPath!!)
            displayResult(fileName, result)
        }
    }

    private fun displayResult(fileName: String, result: ApkInspectionResult) {
        // Displays Risk Score Gauge, Verdict Badge, Package Name, and Red Flags List
        // Tapping 'Proceed to Install' launches PinGateActivity
        val proceedButton: Button? = null // findViewById(R.id.btn_proceed)
        proceedButton?.setOnClickListener {
            val pinIntent = Intent(this, PinGateActivity::class.java).apply {
                putExtra("APK_PATH", apkPath)
            }
            startActivity(pinIntent)
        }
    }
}
