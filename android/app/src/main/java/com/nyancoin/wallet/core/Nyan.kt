package com.nyancoin.wallet.core

import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.math.BigDecimal
import java.security.SecureRandom
import java.text.Normalizer

/** NyanCoin rules and primitives. Everything here matches wallet.py / node.py byte for byte
 *  (checked by unit tests against vectors produced by the Python code). */
object Nyan {
    const val CHAIN_ID = "nyancoin-2"
    const val COIN = 100_000_000L
    const val REWARD0 = 100_000_000L
    const val HALVING = 10_500_000L
    const val MIN_BITS = 20
    const val MAX_BITS = 60
    const val MIN_RELAY_FEE = 1000L
    const val DEFAULT_NODE =
        "https://inter.net.sh:8001#aacf9733d8a238bc0f8a62232e5ab5b804cd3fe80b32e90c58bd70ff52f1fc41"

    /** Fingerprint of the shared consensus constants (same formula as node.py's RULES). */
    val RULES: String = sha256Hex(
        "[\"$CHAIN_ID\",$COIN,$REWARD0,$HALVING,20,$MIN_BITS,$MAX_BITS,10,10,500,7200,9007199254740992,1000000]"
            .toByteArray()
    )

    // ------------------------------------------------------------------ hashing
    fun sha256(b: ByteArray): ByteArray = SHA256Digest().run {
        update(b, 0, b.size); ByteArray(32).also { doFinal(it, 0) }
    }

    fun sha256Hex(b: ByteArray): String = sha256(b).hex()

    fun sha1(b: ByteArray): ByteArray = SHA1Digest().run {
        update(b, 0, b.size); ByteArray(20).also { doFinal(it, 0) }
    }

    fun ByteArray.hex(): String {
        val hx = "0123456789abcdef"
        val sb = StringBuilder(size * 2)
        for (v in this) { sb.append(hx[(v.toInt() shr 4) and 15]); sb.append(hx[v.toInt() and 15]) }
        return sb.toString()
    }

    fun unhex(s: String): ByteArray {
        require(s.length % 2 == 0 && s.all { it in "0123456789abcdef" }) { "bad hex" }
        return ByteArray(s.length / 2) { ((Character.digit(s[2 * it], 16) shl 4) or Character.digit(s[2 * it + 1], 16)).toByte() }
    }

    // ------------------------------------------------------------------ addresses
    fun makeAddress(pubHex: String): String {
        val body = sha256Hex(unhex(pubHex)).substring(0, 40)
        return "NYAN" + body + sha256Hex(body.toByteArray()).substring(0, 4)
    }

    fun validAddress(a: String): Boolean =
        a.length == 48 && a.startsWith("NYAN") && a.substring(4).all { it in "0123456789abcdef" } &&
            sha256Hex(a.substring(4, 44).toByteArray()).substring(0, 4) == a.substring(44)

    fun shortAddress(a: String) = if (a.length > 20) a.take(12) + "…" + a.takeLast(6) else a

    // ------------------------------------------------------------------ BIP39 recovery phrase
    private val WORDS: List<String> by lazy {
        val text = Nyan::class.java.getResourceAsStream("/bip39_english.txt")!!.bufferedReader().readText()
        check(sha256Hex(text.toByteArray()) == "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda") {
            "recovery word list is damaged"
        }
        text.split("\n").filter { it.isNotEmpty() }.also { check(it.size == 2048) }
    }
    private val WORD_INDEX by lazy { WORDS.withIndex().associate { it.value to it.index } }
    private val PREFIX_INDEX by lazy { WORDS.withIndex().associate { it.value.take(4) to it.index } }

    fun newEntropy(words: Int = 24): ByteArray = ByteArray(if (words == 24) 32 else 16).also { SecureRandom().nextBytes(it) }

    fun entropyToWords(ent: ByteArray): List<String> {
        val bits = ent.size * 8
        val cs = bits / 32
        var n = java.math.BigInteger(1, ent).shiftLeft(cs)
            .or(java.math.BigInteger.valueOf(((sha256(ent)[0].toInt() and 0xff) shr (8 - cs)).toLong()))
        val count = (bits + cs) / 11
        val out = ArrayList<String>(count)
        val mask = java.math.BigInteger.valueOf(2047)
        for (i in 0 until count) {
            out.add(WORDS[n.shiftRight(11 * (count - 1 - i)).and(mask).toInt()])
        }
        return out
    }

    class PhraseException(msg: String) : Exception(msg)

    /** Parses a phrase (full words or their first 4 letters, any case, "1." numbering allowed). */
    fun wordsToEntropy(phrase: String): ByteArray {
        val toks = Normalizer.normalize(phrase, Normalizer.Form.NFKD).lowercase().replace(",", " ")
            .split(Regex("\\s+")).filter { it.isNotEmpty() }
            .map { if (it.first().isDigit()) it.substringAfter(".") else it }.filter { it.isNotEmpty() }
        if (toks.size !in setOf(12, 15, 18, 21, 24)) throw PhraseException("A recovery phrase has 12 or 24 words (got ${toks.size}).")
        var n = java.math.BigInteger.ZERO
        toks.forEachIndexed { pos, t ->
            var i = WORD_INDEX[t]
            if (i == null && t.length >= 4) {
                val j = PREFIX_INDEX[t.take(4)]
                if (j != null && WORDS[j].startsWith(t)) i = j
            }
            if (i == null) throw PhraseException("Word #${pos + 1} (\"$t\") isn't in the word list. Check the spelling.")
            n = n.shiftLeft(11).or(java.math.BigInteger.valueOf(i.toLong()))
        }
        val total = 11 * toks.size
        val cs = total / 33
        val entBytes = (total - cs) / 8
        val raw = n.shiftRight(cs).toByteArray()
        val ent = ByteArray(entBytes)
        val copy = minOf(raw.size, entBytes)
        System.arraycopy(raw, raw.size - copy, ent, entBytes - copy, copy)
        val check = n.and(java.math.BigInteger.ONE.shiftLeft(cs).subtract(java.math.BigInteger.ONE)).toInt()
        if (check != (sha256(ent)[0].toInt() and 0xff) shr (8 - cs))
            throw PhraseException("A word is wrong or two words are swapped (checksum failed).")
        return ent
    }

    /** BIP39 seed (PBKDF2-HMAC-SHA512) then SLIP-10 Ed25519 master key: 32-byte private seed. */
    fun entropyToKeySeed(ent: ByteArray): ByteArray {
        val phrase = Normalizer.normalize(entropyToWords(ent).joinToString(" "), Normalizer.Form.NFKD)
        val gen = PKCS5S2ParametersGenerator(SHA512Digest())
        gen.init(phrase.toByteArray(), "mnemonic".toByteArray(), 2048)
        val bip39 = (gen.generateDerivedParameters(512) as KeyParameter).key
        val mac = HMac(SHA512Digest())
        mac.init(KeyParameter("ed25519 seed".toByteArray()))
        mac.update(bip39, 0, bip39.size)
        val out = ByteArray(64)
        mac.doFinal(out, 0)
        return out.copyOf(32)
    }

    class Keys(seed: ByteArray) {
        private val priv = Ed25519PrivateKeyParameters(seed, 0)
        val pubHex: String = priv.generatePublicKey().encoded.hex()
        val address: String = makeAddress(pubHex)
        fun sign(msg: ByteArray): String = Ed25519Signer().run {
            init(true, priv); update(msg, 0, msg.size); generateSignature().hex()
        }
    }

    // ------------------------------------------------------------------ transactions
    /** Canonical signed text: json.dumps(sort_keys=True, separators=(",", ":")) of these 6 fields. */
    fun txBody(from: String, to: String, amount: Long, fee: Long, nonce: Long): String =
        "{\"amount\":$amount,\"chain\":\"$CHAIN_ID\",\"fee\":$fee,\"from\":\"$from\",\"nonce\":$nonce,\"to\":\"$to\"}"

    fun txJson(keys: Keys, to: String, amount: Long, fee: Long, nonce: Long): String {
        val sig = keys.sign(txBody(keys.address, to, amount, fee, nonce).toByteArray())
        return "{\"chain\":\"$CHAIN_ID\",\"from\":\"${keys.address}\",\"pub\":\"${keys.pubHex}\",\"to\":\"$to\"," +
            "\"amount\":$amount,\"fee\":$fee,\"nonce\":$nonce,\"sig\":\"$sig\"}"
    }

    /** "1.5" -> 150000000 units. Null if not a positive amount with at most 8 decimals. */
    fun parseAmount(s: String): Long? = try {
        val v = BigDecimal(s.trim()).movePointRight(8)
        if (v.signum() <= 0 || v.stripTrailingZeros().scale() > 0 || v > BigDecimal(9007199254740992L)) null
        else v.longValueExact()
    } catch (e: Exception) { null }

    fun fmt(units: Double, decimals: Int = 8): String = String.format(java.util.Locale.US, "%,.${decimals}f", units)

    // ------------------------------------------------------------------ mining
    fun reward(height: Long): Long = REWARD0 shr (height / HALVING).toInt().coerceAtMost(63)

    /** The exact header text the node hashes for a coinbase-only block paying `address`. */
    fun workPrefix(bits: Int, height: Long, prev: String, time: Long, address: String): String =
        "{\"bits\":$bits,\"index\":$height,\"prev\":\"$prev\",\"time\":$time,\"txs\":[{\"amount\":${reward(height)}," +
            "\"from\":\"COINBASE\",\"height\":$height,\"to\":\"$address\"}]}|"

    fun meetsBits(d: ByteArray, bits: Int): Boolean {
        var b = bits
        for (byte in d) {
            val v = byte.toInt() and 0xff
            if (b >= 8) { if (v != 0) return false; b -= 8 } else return b == 0 || (v shr (8 - b)) == 0
        }
        return true
    }
}
