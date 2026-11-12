package com.nyancoin.wallet

import com.nyancoin.wallet.core.Miner
import com.nyancoin.wallet.core.NodeClient
import com.nyancoin.wallet.core.NodeException
import com.nyancoin.wallet.core.Nyan
import com.nyancoin.wallet.core.Nyan.hex
import com.nyancoin.wallet.core.WalletFile
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/** Checks the app's crypto against vectors produced by the real Python wallet/node code. */
class CoreTest {
    private val v = JSONObject(javaClass.getResourceAsStream("/vectors.json")!!.bufferedReader().readText())

    @Test fun rulesFingerprintMatchesPython() = assertEquals(v.getString("rules"), Nyan.RULES)

    @Test fun walletsMatchPython() {
        val ws = v.getJSONArray("wallets")
        for (i in 0 until ws.length()) {
            val w = ws.getJSONObject(i)
            val ent = Nyan.unhex(w.getString("entropy"))
            assertEquals(w.getString("words"), Nyan.entropyToWords(ent).joinToString(" "))
            assertEquals(w.getString("entropy"), Nyan.wordsToEntropy(w.getString("words")).hex())
            assertEquals(w.getString("seed"), Nyan.entropyToKeySeed(ent).hex())
            val k = Nyan.Keys(Nyan.entropyToKeySeed(ent))
            assertEquals(w.getString("pub"), k.pubHex)
            assertEquals(w.getString("address"), k.address)
            assertTrue(Nyan.validAddress(k.address))
        }
    }

    @Test fun signaturesMatchPython() {
        val ts = v.getJSONArray("txs")
        for (i in 0 until ts.length()) {
            val t = ts.getJSONObject(i)
            val k = Nyan.Keys(Nyan.entropyToKeySeed(Nyan.unhex(t.getString("entropy"))))
            val body = Nyan.txBody(k.address, "NYANe305634ff1babc194d403b7f2c81266a894ccd75ca41", 250000000, 10000, 3)
            assertEquals(t.getString("body"), body)
            assertEquals(t.getString("sig"), k.sign(body.toByteArray()))
        }
    }

    @Test fun workPrefixMatchesPython() {
        val p = v.getJSONArray("prefixes").getJSONObject(0)
        assertEquals(p.getString("prefix"),
            Nyan.workPrefix(p.getInt("bits"), p.getLong("height"), p.getString("prev"), p.getLong("time"), p.getString("address")))
    }

    @Test fun phraseInputForgiving() {
        val w = v.getJSONArray("wallets").getJSONObject(3)
        val words = w.getString("words").split(" ")
        val messy = words.mapIndexed { i, s -> "${i + 1}.${s.take(4).uppercase()}" }.joinToString("  ")
        assertEquals(w.getString("entropy"), Nyan.wordsToEntropy(messy).hex())
        val swapped = listOf(words[1], words[0]) + words.drop(2)
        assertThrows { Nyan.wordsToEntropy(swapped.joinToString(" ")) }
        assertThrows { Nyan.wordsToEntropy(words.drop(1).joinToString(" ")) }
        assertThrows { Nyan.wordsToEntropy((listOf("zzzz") + words.drop(1)).joinToString(" ")) }
    }

    @Test fun addressesAndAmounts() {
        val a = "NYANe305634ff1babc194d403b7f2c81266a894ccd75ca41"
        assertTrue(Nyan.validAddress(a))
        assertFalse(Nyan.validAddress(a.dropLast(1) + "0"))
        assertFalse(Nyan.validAddress(a.uppercase()))
        assertEquals(150000000L, Nyan.parseAmount("1.5"))
        assertEquals(1L, Nyan.parseAmount("0.00000001"))
        assertEquals(10000000000L, Nyan.parseAmount("100"))
        assertNull(Nyan.parseAmount("0.000000001"))
        assertNull(Nyan.parseAmount("-1"))
        assertNull(Nyan.parseAmount("0"))
        assertNull(Nyan.parseAmount("abc"))
        assertEquals(100000000L, Nyan.reward(1)); assertEquals(50000000L, Nyan.reward(10_500_000))
    }

    @Test fun walletFileRoundTripAndWrongPassword() {
        val ent = Nyan.newEntropy()
        val wf = WalletFile.create(ent, "correct horse battery", n = 1 shl 12)
        assertEquals(ent.hex(), wf.unlockEntropy("correct horse battery").hex())
        assertThrows { wf.unlockEntropy("wrong password!!") }
        // written for the Python cross-check (wallet.py must open it)
        val out = File(System.getProperty("nyan.out") ?: "build/nyan-test").apply { mkdirs() }
        WalletFile.create(Nyan.unhex(v.getJSONArray("wallets").getJSONObject(3).getString("entropy")), "phone-password-123")
            .save(File(out, "phone_wallet.json"))
    }

    /** Live test against a real node: NYAN_TEST_NODE=https://127.0.0.1:8001#PIN */
    @Test fun liveMineAndSend() {
        val url = System.getenv("NYAN_TEST_NODE")
        assumeTrue(url != null)
        val pins = mutableMapOf<String, String>()
        val node = NodeClient(url!!, object : com.nyancoin.wallet.core.PinStore {
            override fun get(hostPort: String) = pins[hostPort]
            override fun put(hostPort: String, pin: String) { pins[hostPort] = pin }
        })
        node.checkRules()
        // wrong pin must be refused before anything is sent
        val bad = NodeClient(url.substringBefore("#") + "#" + "0".repeat(64))
        assertThrows { bad.info() }

        val me = Nyan.Keys(Nyan.entropyToKeySeed(Nyan.unhex(v.getJSONArray("wallets").getJSONObject(1).getString("entropy"))))
        val friend = Nyan.Keys(Nyan.entropyToKeySeed(Nyan.unhex(v.getJSONArray("wallets").getJSONObject(2).getString("entropy"))))
        val miner = Miner(CoroutineScope(SupervisorJob() + Dispatchers.Default))
        miner.start(node, me.address, 2)
        val t0 = System.currentTimeMillis()
        while (miner.state.value.found < 2 && System.currentTimeMillis() - t0 < 120_000) Thread.sleep(500)
        miner.stop()
        while (miner.state.value.running) Thread.sleep(100)
        println("miner: " + miner.state.value)
        assertTrue("mined 2 blocks", miner.state.value.found >= 2)

        val txid = node.send(me, friend.address, Nyan.parseAmount("1.25")!!, Nyan.parseAmount("0.0001")!!)
        assertEquals("pending", node.txStatus(txid).getString("status"))
        val h = node.history(friend.address)
        assertEquals(1, h.getJSONArray("pending").length())
        assertNotEquals(0, node.history(me.address).getJSONArray("confirmed").length())
        println("sent 1.25 NYAN, txid $txid")
    }

    private fun assertThrows(f: () -> Unit) {
        try { f() } catch (e: Exception) { return }
        throw AssertionError("expected an exception")
    }
}
