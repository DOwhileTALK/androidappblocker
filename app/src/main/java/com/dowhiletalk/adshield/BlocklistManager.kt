package com.dowhiletalk.adshield

import android.content.Context
import android.util.Log
import java.io.BufferedReader
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * Loads the set of domains to block.
 *
 * Strategy:
 *  1. Instantly seed with a small built-in list so blocking works offline on
 *     first launch.
 *  2. In the background, download a full hosts-format blocklist (StevenBlack)
 *     and cache it to the app's files dir. On later launches we read the cache.
 *
 * The lookup treats a hit on any parent domain as a hit (so blocking
 * "doubleclick.net" also blocks "ad.doubleclick.net").
 */
object BlocklistManager {

    private const val TAG = "BlocklistManager"
    private const val CACHE_FILE = "blocklist.txt"

    // A widely used, maintained hosts list (0.0.0.0 <domain> lines).
    private const val REMOTE_URL =
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

    // Minimal offline seed so the app blocks something even before the
    // remote list downloads.
    private val SEED = setOf(
        "doubleclick.net",
        "googlesyndication.com",
        "googleadservices.com",
        "google-analytics.com",
        "adservice.google.com",
        "pagead2.googlesyndication.com",
        "ads.yahoo.com",
        "adnxs.com",
        "adsrvr.org",
        "amazon-adsystem.com",
        "app-measurement.com",
        "graph.facebook.com",
        "ads.facebook.com",
        "an.facebook.com",
        "unityads.unity3d.com",
        "applovin.com",
        "chartboost.com",
        "adcolony.com",
        "moatads.com",
        "mopub.com",
        "inmobi.com",
        "startappservice.com",
        "flurry.com",
        "scorecardresearch.com",
        "criteo.com",
        "taboola.com",
        "outbrain.com"
    )

    @Volatile
    private var domains: HashSet<String> = HashSet(SEED)

    init {
        Stats.blocklistSize.set(domains.size.toLong())
    }

    /** True if this exact domain, or any parent domain, is on the blocklist. */
    fun isBlocked(host: String): Boolean {
        val h = host.lowercase().trimEnd('.')
        if (h.isEmpty()) return false
        val set = domains
        if (set.contains(h)) return true
        var idx = h.indexOf('.')
        while (idx != -1) {
            val parent = h.substring(idx + 1)
            if (set.contains(parent)) return true
            idx = h.indexOf('.', idx + 1)
        }
        return false
    }

    /**
     * Load the cached list if present, otherwise seed + kick off a download.
     * Safe to call from a background thread.
     */
    fun load(context: Context) {
        val cache = File(context.filesDir, CACHE_FILE)
        if (cache.exists() && cache.length() > 0) {
            runCatching { parseInto(cache.bufferedReader()) }
                .onFailure { Log.w(TAG, "Failed reading cache", it) }
        }
        // Refresh (or first-time fetch) in the background.
        Thread { refresh(context) }.apply { isDaemon = true }.start()
    }

    private fun refresh(context: Context) {
        try {
            val conn = (URL(REMOTE_URL).openConnection() as HttpURLConnection).apply {
                connectTimeout = 15_000
                readTimeout = 30_000
                requestMethod = "GET"
            }
            if (conn.responseCode != 200) {
                Log.w(TAG, "Blocklist HTTP ${conn.responseCode}")
                return
            }
            val cache = File(context.filesDir, CACHE_FILE)
            conn.inputStream.use { input ->
                cache.outputStream().use { out -> input.copyTo(out) }
            }
            parseInto(cache.bufferedReader())
            Log.i(TAG, "Blocklist refreshed: ${domains.size} domains")
        } catch (e: Exception) {
            Log.w(TAG, "Blocklist refresh failed: ${e.message}")
        }
    }

    private fun parseInto(reader: BufferedReader) {
        val set = HashSet<String>(SEED.size + 200_000)
        set.addAll(SEED)
        reader.useLines { lines ->
            for (raw in lines) {
                val line = raw.trim()
                if (line.isEmpty() || line.startsWith("#")) continue
                // Expected format: "0.0.0.0 domain" or "127.0.0.1 domain".
                val parts = line.split(Regex("\\s+"))
                val domain = when {
                    parts.size >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1") -> parts[1]
                    parts.size == 1 -> parts[0]
                    else -> continue
                }.lowercase().trimEnd('.')
                if (domain.isNotEmpty() && domain != "localhost") {
                    set.add(domain)
                }
            }
        }
        domains = set
        Stats.blocklistSize.set(set.size.toLong())
    }
}
