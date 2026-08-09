package com.dowhiletalk.adshield

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.Executors

/**
 * A local, server-less VPN that only intercepts DNS.
 *
 * How it works:
 *  - We tell Android the system DNS server is a virtual address (VPN_DNS) and
 *    route ONLY that address into our tun device. All other traffic is
 *    untouched, so browsing stays fast and nothing is proxied off-device.
 *  - Every DNS query lands here. We read the requested domain. If it's on a
 *    blocklist we answer NXDOMAIN locally (the ad never loads). Otherwise we
 *    forward the query to a real upstream resolver and relay the answer back.
 *
 * This is the same technique used by DNS66 / AdGuard / Blokada and needs no
 * root.
 */
class AdVpnService : VpnService() {

    companion object {
        private const val TAG = "AdVpnService"

        const val ACTION_START = "com.dowhiletalk.adshield.START"
        const val ACTION_STOP = "com.dowhiletalk.adshield.STOP"

        private const val VPN_ADDRESS = "10.0.0.2"   // our end of the tunnel
        private const val VPN_DNS = "10.0.0.53"      // virtual DNS the system uses
        private const val UPSTREAM_DNS = "8.8.8.8"    // where allowed queries go

        private const val NOTIF_CHANNEL = "adshield_vpn"
        private const val NOTIF_ID = 1001
    }

    @Volatile
    private var running = false
    private var tunnel: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    private val forwarders = Executors.newFixedThreadPool(8)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                return START_NOT_STICKY
            }
            else -> startVpn()
        }
        return START_STICKY
    }

    private fun startVpn() {
        if (running) return
        BlocklistManager.load(applicationContext)

        val builder = Builder()
            .setSession("AdShield")
            .addAddress(VPN_ADDRESS, 32)
            .addDnsServer(VPN_DNS)
            .addRoute(VPN_DNS, 32)   // route ONLY DNS traffic into the tunnel
            .setBlocking(true)

        // Don't filter our own app's traffic (avoids loops).
        runCatching { builder.addDisallowedApplication(packageName) }

        val tun = builder.establish()
        if (tun == null) {
            Log.e(TAG, "establish() returned null — VPN not prepared?")
            stopSelf()
            return
        }
        tunnel = tun
        running = true
        Stats.running = true
        Stats.reset()

        startForeground(NOTIF_ID, buildNotification())

        worker = Thread { runLoop(tun) }.apply {
            isDaemon = true
            name = "adshield-dns"
            start()
        }
        Log.i(TAG, "VPN started")
    }

    private fun runLoop(tun: ParcelFileDescriptor) {
        val input = FileInputStream(tun.fileDescriptor)
        val output = FileOutputStream(tun.fileDescriptor)
        val buffer = ByteArray(32767)
        try {
            while (running) {
                val len = input.read(buffer)
                if (len <= 0) continue
                val packet = buffer.copyOf(len)
                forwarders.submit { handlePacket(packet, output) }
            }
        } catch (e: Exception) {
            if (running) Log.w(TAG, "Read loop ended: ${e.message}")
        } finally {
            runCatching { input.close() }
            runCatching { output.close() }
        }
    }

    /** Parse one IPv4/UDP/DNS packet and either block or forward it. */
    private fun handlePacket(packet: ByteArray, output: FileOutputStream) {
        try {
            if (packet.size < 28) return
            val version = (packet[0].toInt() and 0xF0) ushr 4
            if (version != 4) return
            if ((packet[9].toInt() and 0xFF) != 17) return  // not UDP

            val ihl = (packet[0].toInt() and 0x0F) * 4
            val dnsStart = ihl + 8
            if (dnsStart + 12 > packet.size) return
            val dstPort = readShort(packet, ihl + 2)
            if (dstPort != 53) return

            val srcIp = packet.copyOfRange(12, 16)
            val dstIp = packet.copyOfRange(16, 20)
            val srcPort = readShort(packet, ihl)

            Stats.total.incrementAndGet()

            val (host, questionEnd) = parseQuestion(packet, dnsStart)

            if (host.isNotEmpty() && BlocklistManager.isBlocked(host)) {
                Stats.blocked.incrementAndGet()
                Stats.lastBlockedDomain = host
                val dnsResp = buildNxDomain(packet, dnsStart, questionEnd)
                val reply = buildUdpIpv4(dstIp, srcIp, 53, srcPort, dnsResp)
                writePacket(output, reply)
            } else {
                val dnsPayload = packet.copyOfRange(dnsStart, packet.size)
                forwardUpstream(dnsPayload, srcIp, dstIp, srcPort, output)
            }
        } catch (e: Exception) {
            Log.d(TAG, "packet error: ${e.message}")
        }
    }

    private fun forwardUpstream(
        dnsPayload: ByteArray,
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        output: FileOutputStream
    ) {
        DatagramSocket().use { sock ->
            protect(sock)
            sock.soTimeout = 5000
            val upstream = InetAddress.getByName(UPSTREAM_DNS)
            sock.send(DatagramPacket(dnsPayload, dnsPayload.size, upstream, 53))
            val respBuf = ByteArray(4096)
            val resp = DatagramPacket(respBuf, respBuf.size)
            sock.receive(resp)
            val payload = respBuf.copyOf(resp.length)
            // Response comes FROM the virtual DNS server back TO the app.
            val reply = buildUdpIpv4(dstIp, srcIp, 53, srcPort, payload)
            writePacket(output, reply)
        }
    }

    /** Read the queried domain and return it plus the byte offset after the question. */
    private fun parseQuestion(packet: ByteArray, dnsStart: Int): Pair<String, Int> {
        var pos = dnsStart + 12
        val sb = StringBuilder()
        while (pos < packet.size) {
            val labelLen = packet[pos].toInt() and 0xFF
            pos++
            if (labelLen == 0) break
            if (labelLen and 0xC0 != 0) break // compression pointer — unexpected in a query
            if (pos + labelLen > packet.size) break
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(packet, pos, labelLen, Charsets.US_ASCII))
            pos += labelLen
        }
        val questionEnd = pos + 4 // QTYPE (2) + QCLASS (2)
        return Pair(sb.toString(), questionEnd)
    }

    /** Turn the query into an NXDOMAIN answer: header + echoed question, no records. */
    private fun buildNxDomain(packet: ByteArray, dnsStart: Int, questionEnd: Int): ByteArray {
        val end = questionEnd.coerceAtMost(packet.size)
        val resp = packet.copyOfRange(dnsStart, end)
        if (resp.size < 12) return resp
        resp[2] = 0x81.toByte()  // QR=1, RD=1
        resp[3] = 0x83.toByte()  // RA=1, RCODE=3 (NXDOMAIN)
        resp[4] = 0; resp[5] = 1  // QDCOUNT = 1
        resp[6] = 0; resp[7] = 0  // ANCOUNT = 0
        resp[8] = 0; resp[9] = 0  // NSCOUNT = 0
        resp[10] = 0; resp[11] = 0 // ARCOUNT = 0
        return resp
    }

    // --- packet building helpers ---

    private fun buildUdpIpv4(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val total = 20 + 8 + payload.size
        val pkt = ByteArray(total)
        // IPv4 header
        pkt[0] = 0x45.toByte()     // version 4, IHL 5
        pkt[1] = 0                 // DSCP/ECN
        writeShort(pkt, 2, total)  // total length
        writeShort(pkt, 4, 0)      // identification
        writeShort(pkt, 6, 0x4000) // flags: Don't Fragment
        pkt[8] = 64                // TTL
        pkt[9] = 17                // protocol UDP
        writeShort(pkt, 10, 0)     // checksum placeholder
        System.arraycopy(srcIp, 0, pkt, 12, 4)
        System.arraycopy(dstIp, 0, pkt, 16, 4)
        writeShort(pkt, 10, checksum(pkt, 0, 20))
        // UDP header
        writeShort(pkt, 20, srcPort)
        writeShort(pkt, 22, dstPort)
        writeShort(pkt, 24, 8 + payload.size)
        writeShort(pkt, 26, 0)     // UDP checksum 0 = not used (legal for IPv4)
        System.arraycopy(payload, 0, pkt, 28, payload.size)
        return pkt
    }

    private fun checksum(buf: ByteArray, start: Int, len: Int): Int {
        var sum = 0
        var i = start
        var remaining = len
        while (remaining > 1) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 2
            remaining -= 2
        }
        if (remaining > 0) sum += (buf[i].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv() and 0xFFFF
    }

    private fun readShort(buf: ByteArray, off: Int): Int =
        ((buf[off].toInt() and 0xFF) shl 8) or (buf[off + 1].toInt() and 0xFF)

    private fun writeShort(buf: ByteArray, off: Int, value: Int) {
        buf[off] = ((value ushr 8) and 0xFF).toByte()
        buf[off + 1] = (value and 0xFF).toByte()
    }

    @Synchronized
    private fun writePacket(output: FileOutputStream, packet: ByteArray) {
        runCatching { output.write(packet) }
    }

    // --- notification ---

    private fun buildNotification(): Notification {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIF_CHANNEL,
                "AdShield protection",
                NotificationManager.IMPORTANCE_LOW
            )
            nm.createNotificationChannel(channel)
        }
        val openApp = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            Notification.Builder(this, NOTIF_CHANNEL)
        else
            @Suppress("DEPRECATION") Notification.Builder(this)

        return builder
            .setContentTitle("AdShield is protecting you")
            .setContentText("Filtering ad & tracker domains")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(openApp)
            .setOngoing(true)
            .build()
    }

    private fun stopVpn() {
        running = false
        Stats.running = false
        worker?.interrupt()
        worker = null
        runCatching { tunnel?.close() }
        tunnel = null
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION") stopForeground(true)
        }
        stopSelf()
        Log.i(TAG, "VPN stopped")
    }

    override fun onDestroy() {
        stopVpn()
        forwarders.shutdownNow()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }
}
