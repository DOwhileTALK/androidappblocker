package com.dowhiletalk.adshield

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.dowhiletalk.adshield.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val ui = Handler(Looper.getMainLooper())

    // User approved (or denied) the system VPN consent dialog.
    private val vpnConsent = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnService()
        } else {
            binding.toggle.isChecked = false
        }
    }

    private val notifPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* proceed regardless; notification is optional */ }

    private val refresh = object : Runnable {
        override fun run() {
            render()
            ui.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        maybeAskNotificationPermission()

        binding.toggle.setOnClickListener {
            if (binding.toggle.isChecked) requestVpn() else stopVpnService()
        }
    }

    override fun onResume() {
        super.onResume()
        binding.toggle.isChecked = Stats.running
        ui.post(refresh)
    }

    override fun onPause() {
        super.onPause()
        ui.removeCallbacks(refresh)
    }

    private fun requestVpn() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnConsent.launch(intent)   // first run: show system consent
        } else {
            startVpnService()           // already granted
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, AdVpnService::class.java).apply {
            action = AdVpnService.ACTION_START
        }
        ContextCompat.startForegroundService(this, intent)
        binding.toggle.isChecked = true
    }

    private fun stopVpnService() {
        val intent = Intent(this, AdVpnService::class.java).apply {
            action = AdVpnService.ACTION_STOP
        }
        startService(intent)
        binding.toggle.isChecked = false
    }

    private fun render() {
        val on = Stats.running
        binding.statusText.text = if (on) "Protected" else "Not protected"
        binding.statusSub.text =
            if (on) "Filtering ad & tracker domains" else "Tap the switch to turn on"
        binding.blockedCount.text = Stats.blocked.get().toString()
        binding.totalCount.text = Stats.total.get().toString()
        binding.listSize.text =
            "%,d domains on blocklist".format(Stats.blocklistSize.get())
        binding.lastBlocked.text = Stats.lastBlockedDomain.ifEmpty { "—" }
        if (binding.toggle.isChecked != on) binding.toggle.isChecked = on
    }

    private fun maybeAskNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                this, Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
}
