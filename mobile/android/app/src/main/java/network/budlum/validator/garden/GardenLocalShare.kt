package network.budlum.validator.garden

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.OutputStream
import java.net.Inet4Address
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Local-network invite distribution (sections 5.8, 5.10 and 5.11):
 * - Serves ONLY the installed universal APK file and a simple HTML invite page.
 * - Advertises and discovers Gardens on the local LAN via Android NsdManager (mDNS).
 * Starts when the Invite screen opens and stops as soon as it closes (section 5.6).
 */
class GardenLocalShare(private val context: Context) {

    private val lock = Any()
    private val nsd: NsdManager? =
        context.getSystemService(Context.NSD_SERVICE) as? NsdManager

    private var serverSocket: ServerSocket? = null
    private var serverThread: Thread? = null
    private var workers: ExecutorService? = null
    private val running = AtomicBoolean(false)

    private var activePort: Int = 0
    @Volatile
    private var advertisedRecord: String = ""
    private var regListener: NsdManager.RegistrationListener? = null
    private var discoveryListener: NsdManager.DiscoveryListener? = null

    /**
     * Start the local HTTP share server and mDNS advertisement while the Invite
     * screen is open. Returns `host:port` for the core QR helper (section 5.8).
     */
    fun startShare(record: String): String? {
        synchronized(lock) {
            advertisedRecord = record
            val ip = detectLocalIpv4() ?: return null
            if (!running.get()) {
                val socket = runCatching { ServerSocket(0) }.getOrNull() ?: return null
                activePort = socket.localPort
                serverSocket = socket
                val pool = Executors.newFixedThreadPool(4)
                workers = pool
                running.set(true)
                val thread = Thread({ acceptLoop(socket, pool) }, "garden-local-share").apply {
                    isDaemon = true
                    start()
                }
                serverThread = thread
            }
            if (record.isNotBlank() && activePort > 0) {
                restartMdnsAdvertising(record, activePort)
            }
            return "$ip:$activePort"
        }
    }

    /** Stop HTTP sharing and mDNS advertisement (section 5.6). */
    fun stopShare() {
        synchronized(lock) {
            running.set(false)
            activePort = 0
            advertisedRecord = ""
            runCatching { serverSocket?.close() }
            serverSocket = null
            serverThread = null
            workers?.shutdownNow()
            workers = null
            stopMdnsAdvertising()
        }
    }

    /** Discover Gardens announced over mDNS on the local LAN (section 5.10). */
    fun startDiscovery(onRecordFound: (label: String, record: String) -> Unit) {
        val manager = nsd ?: return
        synchronized(lock) {
            stopDiscoveryLocked(manager)
            val listener = object : NsdManager.DiscoveryListener {
                override fun onDiscoveryStarted(regType: String) {}
                override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                    if (!serviceInfo.serviceType.contains("budlum-garden")) return
                    @Suppress("DEPRECATION")
                    runCatching {
                        manager.resolveService(serviceInfo, object : NsdManager.ResolveListener {
                            override fun onResolveFailed(info: NsdServiceInfo, errorCode: Int) {}
                            override fun onServiceResolved(resolved: NsdServiceInfo) {
                                val record = assembleTxtRecord(resolved.attributes)
                                if (record.isNotBlank()) {
                                    onRecordFound(resolved.serviceName, record)
                                }
                            }
                        })
                    }
                }

                override fun onServiceLost(serviceInfo: NsdServiceInfo) {}
                override fun onDiscoveryStopped(serviceType: String) {}
                override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                    runCatching { manager.stopServiceDiscovery(this) }
                }

                override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {}
            }
            discoveryListener = listener
            runCatching {
                manager.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, listener)
            }
        }
    }

    fun stopDiscovery() {
        val manager = nsd ?: return
        synchronized(lock) { stopDiscoveryLocked(manager) }
    }

    private fun stopDiscoveryLocked(manager: NsdManager) {
        discoveryListener?.let { listener ->
            runCatching { manager.stopServiceDiscovery(listener) }
        }
        discoveryListener = null
    }

    private fun restartMdnsAdvertising(record: String, port: Int) {
        stopMdnsAdvertising()
        val manager = nsd ?: return
        val info = NsdServiceInfo().apply {
            serviceName = "BudlumGarden"
            serviceType = SERVICE_TYPE
            setPort(port)
            val chunks = chunkRecord(record)
            chunks.forEachIndexed { idx, part ->
                setAttribute("r$idx", part)
            }
        }
        val listener = object : NsdManager.RegistrationListener {
            override fun onServiceRegistered(nsdServiceInfo: NsdServiceInfo) {}
            override fun onRegistrationFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {}
            override fun onServiceUnregistered(arg0: NsdServiceInfo) {}
            override fun onUnregistrationFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {}
        }
        regListener = listener
        runCatching { manager.registerService(info, NsdManager.PROTOCOL_DNS_SD, listener) }
    }

    private fun stopMdnsAdvertising() {
        val manager = nsd ?: return
        regListener?.let { listener ->
            runCatching { manager.unregisterService(listener) }
        }
        regListener = null
    }

    private fun acceptLoop(socket: ServerSocket, pool: ExecutorService) {
        while (running.get() && !socket.isClosed) {
            val client = runCatching { socket.accept() }.getOrNull() ?: break
            pool.execute { handleClient(client) }
        }
    }

    private fun handleClient(client: Socket) {
        client.use { sock ->
            runCatching {
                sock.soTimeout = CLIENT_TIMEOUT_MS
                val requestLine = readBoundedLine(BufferedInputStream(sock.getInputStream()))
                    ?: return
                val parts = requestLine.split(' ')
                if (parts.size < 2 || parts[0] != "GET") {
                    writeResponse(sock.getOutputStream(), 405, "text/plain; charset=utf-8", "Method Not Allowed".toByteArray())
                    return
                }
                val path = parts[1].substringBefore('?')
                when (path) {
                    "/", "/g" -> {
                        val html = inviteHtmlPage(advertisedRecord).toByteArray(StandardCharsets.UTF_8)
                        writeResponse(sock.getOutputStream(), 200, "text/html; charset=utf-8", html)
                    }
                    APK_PATH -> streamInstalledApk(sock.getOutputStream())
                    else -> writeResponse(sock.getOutputStream(), 404, "text/plain; charset=utf-8", "Not Found".toByteArray())
                }
            }
        }
    }

    private fun streamInstalledApk(out: OutputStream) {
        val apkPath = context.applicationInfo.publicSourceDir ?: context.packageCodePath
        val apkFile = File(apkPath)
        if (!apkFile.isFile || !apkFile.canRead()) {
            writeResponse(out, 404, "text/plain; charset=utf-8", "APK Unavailable".toByteArray())
            return
        }
        val headers = (
            "HTTP/1.1 200 OK\r\n" +
                "Content-Type: application/vnd.android.package-archive\r\n" +
                "Content-Disposition: attachment; filename=\"budlum-garden.apk\"\r\n" +
                "Content-Length: ${apkFile.length()}\r\n" +
                "Connection: close\r\n\r\n"
            ).toByteArray(StandardCharsets.US_ASCII)
        out.write(headers)
        FileInputStream(apkFile).use { input ->
            val buf = ByteArray(16 * 1024)
            while (true) {
                val read = input.read(buf)
                if (read <= 0) break
                out.write(buf, 0, read)
            }
        }
        out.flush()
    }

    private fun writeResponse(out: OutputStream, status: Int, contentType: String, body: ByteArray) {
        val reason = when (status) {
            200 -> "OK"
            404 -> "Not Found"
            405 -> "Method Not Allowed"
            else -> "Error"
        }
        val head = (
            "HTTP/1.1 $status $reason\r\n" +
                "Content-Type: $contentType\r\n" +
                "Cache-Control: no-store\r\n" +
                "Content-Length: ${body.size}\r\n" +
                "Connection: close\r\n\r\n"
            ).toByteArray(StandardCharsets.US_ASCII)
        out.write(head)
        out.write(body)
        out.flush()
    }

    private fun readBoundedLine(input: BufferedInputStream): String? {
        val buf = ByteArrayOutputStream(256)
        while (buf.size() < MAX_HEADER_LINE_BYTES) {
            val b = input.read()
            if (b == -1) break
            if (b == '\n'.code) break
            if (b != '\r'.code) buf.write(b)
        }
        val line = buf.toString(StandardCharsets.US_ASCII.name())
        return line.takeIf { it.isNotBlank() && buf.size() < MAX_HEADER_LINE_BYTES }
    }

    companion object {
        const val SERVICE_TYPE = "_budlum-garden._tcp."
        const val APK_PATH = "/budlum-garden.apk"
        private const val CLIENT_TIMEOUT_MS = 5_000
        private const val MAX_HEADER_LINE_BYTES = 2_048
        private const val TXT_CHUNK_LEN = 160

        fun chunkRecord(record: String): List<String> =
            if (record.isEmpty()) emptyList() else record.chunked(TXT_CHUNK_LEN)

        fun assembleTxtRecord(attrs: Map<String, ByteArray>?): String {
            if (attrs == null || attrs.isEmpty()) return ""
            val parts = (0..7).mapNotNull { idx ->
                attrs["r$idx"]?.toString(StandardCharsets.UTF_8)
            }
            return parts.joinToString("")
        }

        fun isPrivateOrCgnatIpv4(addr: Inet4Address): Boolean {
            if (addr.isSiteLocalAddress) return true
            val raw = addr.address
            val first = raw[0].toInt() and 0xFF
            val second = raw[1].toInt() and 0xFF
            return first == 100 && second in 64..127
        }

        fun detectLocalIpv4(): String? {
            val interfaces = runCatching { NetworkInterface.getNetworkInterfaces() }.getOrNull()
                ?: return null
            while (interfaces.hasMoreElements()) {
                val iface = interfaces.nextElement()
                if (!iface.isUp || iface.isLoopback) continue
                val addrs = iface.inetAddresses
                while (addrs.hasMoreElements()) {
                    val addr = addrs.nextElement()
                    if (addr is Inet4Address &&
                        !addr.isLoopbackAddress &&
                        !addr.isLinkLocalAddress &&
                        isPrivateOrCgnatIpv4(addr)
                    ) {
                        return addr.hostAddress ?: continue
                    }
                }
            }
            return null
        }

        fun escapeHtml(text: String): String = buildString(text.length) {
            for (c in text) {
                when (c) {
                    '<' -> append("&lt;")
                    '>' -> append("&gt;")
                    '&' -> append("&amp;")
                    '"' -> append("&quot;")
                    '\'' -> append("&#39;")
                    else -> append(c)
                }
            }
        }

        fun inviteHtmlPage(fallbackRecord: String): String {
            val safeRecord = escapeHtml(fallbackRecord)
            val hasRecord = fallbackRecord.startsWith("budlum://garden/join#")
            val openHref = if (hasRecord) safeRecord else "budlum://garden/join"
            return """
                <!doctype html>
                <html lang="en">
                <head>
                  <meta charset="utf-8" />
                  <meta name="viewport" content="width=device-width,initial-scale=1" />
                  <title>Join Budlum Garden</title>
                  <style>
                    body { font-family: sans-serif; max-width: 480px; margin: 2rem auto; padding: 0 1rem; }
                    a.btn { display: block; padding: 14px 18px; margin: 12px 0; text-align: center;
                            border-radius: 8px; text-decoration: none; font-weight: 600; background: #14532d; color: #fff; }
                    a.secondary { background: #1f2937; }
                  </style>
                </head>
                <body>
                  <h1>Join Budlum Garden</h1>
                  <p>Install the APK on this network, then open the invite in Budlum.</p>
                  <a class="btn" href="$APK_PATH">Download APK</a>
                  <a id="open-link" class="btn secondary" href="$openHref">Open in Budlum</a>
                  <script>
                    (function () {
                      if (window.location.hash && window.location.hash.length > 1) {
                        document.getElementById("open-link").href = "budlum://garden/join" + window.location.hash;
                      }
                    })();
                  </script>
                </body>
                </html>
            """.trimIndent()
        }
    }
}
