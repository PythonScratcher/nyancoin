package com.nyancoin.wallet.core

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException
import java.net.URI
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.X509TrustManager

class NodeException(msg: String) : Exception(msg)

/** Stores node keys seen without a #PIN (trust on first use, like SSH). */
interface PinStore {
    fun get(hostPort: String): String?
    fun put(hostPort: String, pin: String)
}

/**
 * HTTPS client for a NyanCoin node. Nodes use self-signed certificates; their identity is the
 * SHA-256 of their public key (the "pin"). With a #PIN in the URL that pin is required on every
 * connection; without one, the first key seen is remembered and any later change is refused.
 */
class NodeClient(nodeUrl: String, private val pins: PinStore? = null) {
    val base: String
    private val hostPort: String
    val pin: String?

    init {
        val url = nodeUrl.trim().ifEmpty { Nyan.DEFAULT_NODE }
        val (b, p) = url.split("#", limit = 2).let { it[0].trimEnd('/') to it.getOrNull(1)?.lowercase() }
        val u = try { URI(b) } catch (e: Exception) { throw NodeException("That node address isn't valid.") }
        if (u.scheme != "https" || u.host.isNullOrEmpty() || u.port <= 0)
            throw NodeException("Node address must look like https://host:8001#PIN")
        if (p != null && (p.length != 64 || !p.all { it in "0123456789abcdef" }))
            throw NodeException("The #PIN must be 64 hex characters.")
        base = b
        hostPort = "${u.host.lowercase()}:${u.port}"
        pin = p
    }

    @Volatile var seenPin: String? = null
        private set

    private val trust = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = throw CertificateException()
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            if (chain.isEmpty()) throw CertificateException("no certificate")
            val got = Nyan.sha256Hex(chain[0].publicKey.encoded)
            seenPin = got
            val expected = pin ?: pins?.get(hostPort)
            if (expected == null) pins?.put(hostPort, got)
            else if (got != expected) throw CertificateException(
                if (pin != null) "PIN_MISMATCH" else "KEY_CHANGED")
        }
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    private val http: OkHttpClient = OkHttpClient.Builder()
        .sslSocketFactory(SSLContext.getInstance("TLS").apply { init(null, arrayOf(trust), null) }.socketFactory, trust)
        .hostnameVerifier { _, _ -> true }            // identity = the pinned key, checked above
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .followRedirects(false)
        .build()

    private fun call(path: String, body: String? = null): JSONObject {
        val rb = Request.Builder().url(base + path)
        if (body != null) rb.post(body.toRequestBody("application/json".toMediaType()))
        try {
            http.newCall(rb.build()).execute().use { r ->
                val text = r.body?.string() ?: ""
                if (r.code == 400 && path == "/tx")
                    throw NodeException("The node refused the payment. Usually: not enough balance, the fee is too low, " +
                        "or an earlier payment is still waiting. Wait a moment and try again.")
                if (r.code == 429) throw NodeException("The node says we're sending too many requests. Wait a minute.")
                if (r.code != 200) throw NodeException("The node answered HTTP ${r.code}.")
                return JSONObject(text)
            }
        } catch (e: SSLHandshakeException) {
            val m = generateSequence(e as Throwable) { it.cause }.mapNotNull { it.message }.joinToString(" ")
            throw NodeException(when {
                "PIN_MISMATCH" in m -> "Security check failed: this server is NOT the node your #PIN belongs to. Nothing was sent."
                "KEY_CHANGED" in m -> "Security check failed: this node's key changed since last time. Nothing was sent."
                else -> "Secure connection to the node failed."
            })
        } catch (e: NodeException) {
            throw e
        } catch (e: IOException) {
            throw NodeException("Can't reach the node. Check your internet connection and the node address.")
        }
    }

    fun info(): JSONObject = call("/info")
    fun history(addr: String, limit: Int = 100): JSONObject = call("/history/$addr?limit=$limit")
    fun nextNonce(addr: String): Long = call("/balance/$addr").getLong("next_nonce")
    fun txStatus(txid: String): JSONObject = call("/tx/$txid")
    fun work(addr: String): JSONObject = call("/work?addr=$addr")
    fun submit(job: String, nonce: Long): JSONObject = call("/submit", "{\"job\":\"$job\",\"nonce\":$nonce}")

    /** Refuses nodes running different consensus rules (version mismatch). */
    fun checkRules() {
        if (info().optString("rules") != Nyan.RULES)
            throw NodeException("This node runs different NyanCoin rules. Update the app or pick another node.")
    }

    /** Signs and sends a payment. Returns the transaction id. */
    fun send(keys: Nyan.Keys, to: String, amount: Long, fee: Long): String {
        checkRules()
        val nonce = nextNonce(keys.address)
        val r = call("/tx", Nyan.txJson(keys, to, amount, fee, nonce))
        if (!r.optBoolean("ok")) throw NodeException("The node didn't accept the payment (${r.optString("result")}).")
        return r.getString("txid")
    }
}
