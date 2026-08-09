package com.dowhiletalk.adshield

import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * Tiny process-wide holder for live numbers the UI polls once a second.
 * Kept deliberately simple: no DI, no observers, just atomics.
 */
object Stats {
    /** Whether the filtering VPN is currently running. */
    @Volatile
    var running: Boolean = false

    /** DNS queries answered locally because the domain was on a blocklist. */
    val blocked = AtomicInteger(0)

    /** DNS queries seen in total (blocked + allowed/forwarded). */
    val total = AtomicInteger(0)

    /** Last domain we blocked, shown in the UI so it feels alive. */
    @Volatile
    var lastBlockedDomain: String = ""

    /** Number of domains loaded into the active blocklist. */
    val blocklistSize = AtomicLong(0)

    fun reset() {
        blocked.set(0)
        total.set(0)
        lastBlockedDomain = ""
    }
}
