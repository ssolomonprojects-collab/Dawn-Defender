package com.dawndefender.app

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Environment
import android.os.FileObserver
import android.os.IBinder
import androidx.core.app.NotificationCompat
import java.io.File

class DownloadWatcherService : Service() {

    private var fileObserver: FileObserver? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startWatchingDownloads()
    }

    private fun startWatchingDownloads() {
        val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            fileObserver = object : FileObserver(downloadsDir, CREATE or CLOSE_WRITE) {
                override fun onEvent(event: Int, path: String?) {
                    if (path != null && path.endsWith(".apk", ignoreCase = true)) {
                        val apkFile = File(downloadsDir, path)
                        notifyApkDetected(apkFile.absolutePath, path)
                    }
                }
            }
        } else {
            @Suppress("DEPRECATION")
            fileObserver = object : FileObserver(downloadsDir.absolutePath, CREATE or CLOSE_WRITE) {
                override fun onEvent(event: Int, path: String?) {
                    if (path != null && path.endsWith(".apk", ignoreCase = true)) {
                        val apkFile = File(downloadsDir, path)
                        notifyApkDetected(apkFile.absolutePath, path)
                    }
                }
            }
        }
        fileObserver?.startWatching()
    }

    private fun notifyApkDetected(apkPath: String, fileName: String) {
        val intent = Intent(this, ApkScanActivity::class.java).apply {
            putExtra("APK_PATH", apkPath)
            putExtra("FILE_NAME", fileName)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }

        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("🛡️ Dawn Defender: New APK Detected")
            .setContentText("Tap to inspect permissions for $fileName before installation")
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.notify(1001, notification)
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Dawn Defender Downloads Watcher",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Notifies user when a new APK is downloaded"
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        fileObserver?.stopWatching()
        super.onDestroy()
    }

    companion object {
        const val CHANNEL_ID = "dawn_defender_apk_watcher"
    }
}
