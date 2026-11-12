package com.nyancoin.wallet

import android.app.Application
import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.nyancoin.wallet.core.Miner
import com.nyancoin.wallet.core.NodeClient
import com.nyancoin.wallet.core.NodeException
import com.nyancoin.wallet.core.Nyan
import com.nyancoin.wallet.core.PinStore
import com.nyancoin.wallet.core.WalletFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File

/** One payment row in the activity list, seen from our address. */
data class Activity(
    val kind: Kind, val amount: Double, val other: String?, val confirmations: Int,
    val height: Long?, val txid: String?, val fee: Double,
) {
    enum class Kind { RECEIVED, SENT, SELF, REWARD }
}

class AppViewModel(app: Application) : AndroidViewModel(app) {
    private val prefs = app.getSharedPreferences("nyancoin", Context.MODE_PRIVATE)
    private val walletPath = File(app.filesDir, "wallet.json")

    var wallet by mutableStateOf(WalletFile.load(walletPath)); private set
    var nodeUrl by mutableStateOf(prefs.getString("node", Nyan.DEFAULT_NODE) ?: Nyan.DEFAULT_NODE); private set
    var balance by mutableStateOf<Double?>(null); private set
    var pendingIn by mutableStateOf(0.0); private set
    var pendingOut by mutableStateOf(0.0); private set
    var activity by mutableStateOf<List<Activity>>(emptyList()); private set
    var chainHeight by mutableStateOf<Long?>(null); private set
    var nodeError by mutableStateOf<String?>(null); private set
    var refreshing by mutableStateOf(false); private set

    var threads by mutableStateOf(prefs.getInt("threads", (Runtime.getRuntime().availableProcessors() - 1).coerceAtLeast(1))); private set
    var keepAwake by mutableStateOf(prefs.getBoolean("keepAwake", true)); private set
    val maxThreads = Runtime.getRuntime().availableProcessors()
    val miner = Miner(viewModelScope)

    private val pinStore = object : PinStore {
        override fun get(hostPort: String) = prefs.getString("pin:$hostPort", null)
        override fun put(hostPort: String, pin: String) { prefs.edit().putString("pin:$hostPort", pin).apply() }
    }

    fun node() = NodeClient(nodeUrl, pinStore)

    init {
        viewModelScope.launch {
            while (true) {
                if (wallet != null) refresh()
                delay(15_000)
            }
        }
    }

    /** Screenshot tests fill the screens with sample data instead of asking a node. */
    internal var demoMode = false
    internal fun demo(balance: Double, pendingIn: Double, height: Long, activity: List<Activity>) {
        demoMode = true; refreshing = false; nodeError = null
        this.balance = balance; this.pendingIn = pendingIn; chainHeight = height; this.activity = activity
    }

    fun refresh() {
        if (demoMode) return
        val w = wallet ?: return
        if (refreshing) return
        refreshing = true
        viewModelScope.launch {
            try {
                val h = withContext(Dispatchers.IO) { node().history(w.address, 100) }
                apply(h, w.address)
                nodeError = null
            } catch (e: NodeException) {
                nodeError = e.message
            } catch (e: Exception) {
                nodeError = "Unexpected answer from the node."
            } finally {
                refreshing = false
            }
        }
    }

    private fun apply(h: JSONObject, me: String) {
        balance = h.getDouble("balance")
        chainHeight = h.getLong("tip")
        val list = ArrayList<Activity>()
        var pin = 0.0; var pout = 0.0
        val pend = h.getJSONArray("pending")
        for (i in 0 until pend.length()) {
            val t = pend.getJSONObject(i)
            val a = parse(t, me, 0, null)
            if (a.kind == Activity.Kind.RECEIVED) pin += a.amount else pout += -a.amount
            list.add(a)
        }
        val conf = h.getJSONArray("confirmed")
        for (i in 0 until conf.length()) {
            val t = conf.getJSONObject(i)
            list.add(parse(t, me, t.getInt("confirmations"), t.getLong("height")))
        }
        pendingIn = pin; pendingOut = pout; activity = list
    }

    private fun parse(t: JSONObject, me: String, conf: Int, height: Long?): Activity {
        val amt = t.getDouble("amount"); val fee = t.optDouble("fee", 0.0)
        val txid = if (t.isNull("txid")) null else t.optString("txid")
        return when {
            t.optString("kind") == "reward" -> Activity(Activity.Kind.REWARD, amt, null, conf, height, null, 0.0)
            t.getString("from") == me && t.getString("to") == me -> Activity(Activity.Kind.SELF, -fee, me, conf, height, txid, fee)
            t.getString("from") == me -> Activity(Activity.Kind.SENT, -(amt + fee), t.getString("to"), conf, height, txid, fee)
            else -> Activity(Activity.Kind.RECEIVED, amt, t.getString("from"), conf, height, txid, 0.0)
        }
    }

    // ------------------------------------------------------------------ wallet lifecycle
    suspend fun createWallet(entropy: ByteArray, password: String) {
        val wf = withContext(Dispatchers.Default) { WalletFile.create(entropy, password).also { it.save(walletPath) } }
        balance = null; activity = emptyList()
        wallet = wf
        refresh()
    }

    /** Throws WalletFile.WrongPassword. */
    suspend fun unlock(password: String): Nyan.Keys =
        withContext(Dispatchers.Default) { wallet!!.unlock(password) }

    suspend fun revealPhrase(password: String): List<String> =
        withContext(Dispatchers.Default) { Nyan.entropyToWords(wallet!!.unlockEntropy(password)) }

    suspend fun send(keys: Nyan.Keys, to: String, amount: Long, fee: Long): String {
        val txid = withContext(Dispatchers.IO) { node().send(keys, to, amount, fee) }
        refresh()
        return txid
    }

    fun removeWallet() {
        miner.stop()
        walletPath.delete()
        wallet = null; balance = null; activity = emptyList()
    }

    // ------------------------------------------------------------------ settings
    /** Validates and saves a node address; returns an error message or null. */
    suspend fun setNode(url: String): String? {
        val u = url.trim().ifEmpty { Nyan.DEFAULT_NODE }
        return try {
            val n = NodeClient(u, pinStore)
            withContext(Dispatchers.IO) { n.checkRules() }
            nodeUrl = u
            prefs.edit().putString("node", u).apply()
            refresh()
            null
        } catch (e: NodeException) { e.message }
    }

    fun changeThreads(n: Int) { threads = n.coerceIn(1, maxThreads); prefs.edit().putInt("threads", threads).apply() }
    fun changeKeepAwake(b: Boolean) { keepAwake = b; prefs.edit().putBoolean("keepAwake", b).apply() }

    fun startMining() { wallet?.let { miner.start(node(), it.address, threads) } }

    override fun onCleared() { miner.stop() }
}
