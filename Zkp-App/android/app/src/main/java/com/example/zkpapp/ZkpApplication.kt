package com.example.zkpapp

import android.app.Application
import android.content.Intent
import android.os.Process
import android.util.Log
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.ProcessLifecycleOwner
import java.io.PrintWriter
import java.io.StringWriter

class ZkpApplication : Application() {

    companion object {
        // 🛡️ Global App Lock State
        var isAppLocked = false
    }

    override fun onCreate() {
        super.onCreate()

        // ==========================================
        // 🛡️ 1. GLOBAL APP LOCK (DAY 91 - SECURITY)
        // Yeh puri app ke minimize/maximize hone par nazar rakhega
        // ==========================================
        ProcessLifecycleOwner.get().lifecycle.addObserver(LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) {
                // App background mein chali gayi
                isAppLocked = true
                Log.d("ZkpSecurity", "🔒 App Minimized. Session Locked!")
            } else if (event == Lifecycle.Event.ON_START) {
                // App wapis foreground mein aayi
                if (isAppLocked) {
                    Log.d("ZkpSecurity", "☝️ App Opened. Launching Lock Screen!")
                    val intent = Intent(this, LockActivity::class.java)
                    intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                    startActivity(intent)
                }
            }
        })

        // ==========================================
        // 🦁 2. GLOBAL CRASH HANDLER (EXISTING)
        // Yeh puri app ke errors par nazar rakhega
        // ==========================================
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            handleUncaughtException(throwable)
        }
    }

    private fun handleUncaughtException(e: Throwable) {
        val sw = StringWriter()
        e.printStackTrace(PrintWriter(sw))
        val stackTrace = sw.toString()

        Log.e("ZkpCrash", stackTrace)

        // Error Activity ko start karo
        val intent = Intent(applicationContext, ErrorActivity::class.java)
        intent.putExtra("error_log", stackTrace)
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        startActivity(intent)

        Process.killProcess(Process.myPid())
        System.exit(1)
    }
}