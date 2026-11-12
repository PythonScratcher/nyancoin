package com.nyancoin.wallet.core

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.bouncycastle.crypto.digests.SHA256Digest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.random.Random

data class MinerState(
    val running: Boolean = false,
    val status: String = "Stopped",
    val hashrate: Double = 0.0,
    val height: Long = 0,
    val bits: Int = 0,
    val found: Int = 0,
    val late: Int = 0,
    val log: List<String> = emptyList(),
)

/**
 * Phone miner. Uses the node's small "work" API, rebuilds the block header itself so the
 * block can only ever pay OUR address, and refuses work that differs by even one byte.
 * Hashing runs on plain low-priority threads, one per chosen core.
 */
class Miner(private val scope: CoroutineScope) {
    private val _state = MutableStateFlow(MinerState())
    val state: StateFlow<MinerState> = _state
    private var job: Job? = null
    private val stopAll = AtomicBoolean(false)

    fun start(node: NodeClient, address: String, threads: Int) {
        if (job?.isActive == true) return
        stopAll.set(false)
        _state.update { it.copy(running = true, status = "Connecting…") }
        job = scope.launch(Dispatchers.IO) {
            try {
                node.checkRules()
                log("Connected. Mining with $threads core${if (threads > 1) "s" else ""}.")
                while (isActive && !stopAll.get()) mineOne(node, address, threads)
            } catch (e: NodeException) {
                log("⚠ ${e.message}")
                _state.update { it.copy(status = e.message ?: "Error") }
            } finally {
                _state.update { it.copy(running = false, hashrate = 0.0,
                    status = if (stopAll.get() || it.status.startsWith("Mining") || it.status.startsWith("Connecting") ||
                        it.status.startsWith("Waiting")) "Stopped" else it.status) }
            }
        }
    }

    internal fun demo(s: MinerState) { _state.value = s }

    fun stop() {
        stopAll.set(true)
        _state.update { it.copy(status = "Stopping…") }
    }

    private fun log(msg: String) {
        val t = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        _state.update { it.copy(log = (listOf("$t  $msg") + it.log).take(60)) }
    }

    private suspend fun mineOne(node: NodeClient, address: String, threads: Int) {
        val w = try { node.work(address) } catch (e: NodeException) {
            _state.update { it.copy(status = "Waiting for node…", hashrate = 0.0) }
            delay(5000); return
        }
        val height = w.getLong("height"); val bits = w.getInt("bits")
        val prev = w.getString("prev"); val time = w.getLong("time"); val jobId = w.getString("job")
        val mine = Nyan.workPrefix(bits, height, prev, time, address)
        if (bits !in Nyan.MIN_BITS..Nyan.MAX_BITS || prev.length != 64 || mine != w.getString("prefix")) {
            log("⚠ Node sent work that doesn't pay you correctly. Refused.")
            delay(10000); return
        }
        _state.update { it.copy(status = "Mining", height = height, bits = bits) }

        val base = SHA256Digest().apply { val p = mine.toByteArray(); update(p, 0, p.size) }
        val winner = AtomicLong(-1)
        val stop = AtomicBoolean(false)
        val hashes = AtomicLong(0)
        val start = Random.nextLong(0, 1L shl 40)
        val workers = (0 until threads).map { i ->
            Thread {
                val d = SHA256Digest()
                val out = ByteArray(32)
                val buf = ByteArray(20)
                var n = start + i
                var c = 0
                while (true) {
                    d.reset(base)                                  // copy the header midstate
                    var v = n; var k = 20
                    do { buf[--k] = ('0'.code + (v % 10).toInt()).toByte(); v /= 10 } while (v > 0)
                    d.update(buf, k, 20 - k)
                    d.doFinal(out, 0)
                    if (Nyan.meetsBits(out, bits)) { winner.compareAndSet(-1, n); stop.set(true); break }
                    n += threads
                    if (++c == 4096) { c = 0; hashes.addAndGet(4096); if (stop.get()) break }
                }
            }.apply { priority = Thread.MIN_PRIORITY; isDaemon = true; start() }
        }

        val t0 = System.currentTimeMillis()
        var lastT = t0; var lastH = 0L; var lastTip = t0
        try {
            while (winner.get() < 0 && !stopAll.get()) {
                delay(1000)
                val now = System.currentTimeMillis()
                val h = hashes.get()
                _state.update { it.copy(hashrate = (h - lastH) * 1000.0 / (now - lastT).coerceAtLeast(1)) }
                lastT = now; lastH = h
                if (now - lastTip >= 4000) {                      // someone else found this block?
                    lastTip = now
                    try { if (node.info().getString("tip") != prev) break } catch (_: NodeException) {}
                }
                if (now - t0 > 30000) break                        // fresh timestamp now and then
            }
        } finally {
            stop.set(true)
            workers.forEach { it.join(2000) }
        }
        val n = winner.get()
        if (n >= 0) {
            try {
                val r = node.submit(jobId, n)
                if (r.optBoolean("ok")) {
                    _state.update { it.copy(found = it.found + 1) }
                    log("★ Found block $height! +${Nyan.fmt(Nyan.reward(height) / Nyan.COIN.toDouble(), 2)} NYAN")
                } else {
                    _state.update { it.copy(late = it.late + 1) }
                    log("Block $height: someone else was faster (${r.optString("result")}).")
                }
            } catch (e: NodeException) { log("⚠ Couldn't submit block $height: ${e.message}") }
        }
    }
}
