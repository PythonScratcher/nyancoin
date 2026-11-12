package com.nyancoin.wallet.core

import com.nyancoin.wallet.core.Nyan.hex
import org.bouncycastle.crypto.generators.SCrypt
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.json.JSONObject
import java.io.File
import java.security.SecureRandom

/** Encrypted wallet file, same format as wallet.py (version 3): the recovery phrase's entropy,
 *  encrypted with ChaCha20-Poly1305 under a scrypt key derived from the password. The address
 *  is authenticated as associated data, so a swapped address is detected. */
class WalletFile private constructor(val json: JSONObject) {
    val address: String get() = json.getString("address")
    val wordCount: Int get() = json.optInt("words", 24)

    class WrongPassword : Exception("Wrong password.")

    /** Decrypts the recovery-phrase entropy. Throws WrongPassword. */
    fun unlockEntropy(password: String): ByteArray {
        val k = json.getJSONObject("kdf")
        require(k.getString("name") == "scrypt")
        val n = k.getInt("n")
        require(n in 1024..(1 shl 22) && k.getInt("r") in 1..32 && k.getInt("p") in 1..16) { "unsupported wallet" }
        val key = SCrypt.generate(password.toByteArray(), Nyan.unhex(k.getString("salt")), n, k.getInt("r"), k.getInt("p"), 32)
        return try {
            aead(false, key, Nyan.unhex(json.getString("nonce")), Nyan.unhex(json.getString("ct")), address.toByteArray())
        } catch (e: Exception) {
            throw WrongPassword()
        }
    }

    /** Unlocks and returns signing keys, double-checking they belong to this wallet's address. */
    fun unlock(password: String): Nyan.Keys {
        val keys = Nyan.Keys(Nyan.entropyToKeySeed(unlockEntropy(password)))
        check(keys.address == address) { "wallet file is inconsistent" }
        return keys
    }

    fun save(f: File) {
        val tmp = File(f.path + ".tmp")
        tmp.writeText(json.toString())
        if (!tmp.renameTo(f)) { f.delete(); check(tmp.renameTo(f)) }
    }

    companion object {
        /** scrypt cost. 2^15 (~32 MB, well under a second on phones). wallet.py accepts 2^10..2^22. */
        const val PHONE_SCRYPT_N = 1 shl 15

        fun create(entropy: ByteArray, password: String, n: Int = PHONE_SCRYPT_N): WalletFile {
            val keys = Nyan.Keys(Nyan.entropyToKeySeed(entropy))
            val rnd = SecureRandom()
            val salt = ByteArray(16).also { rnd.nextBytes(it) }
            val nonce = ByteArray(12).also { rnd.nextBytes(it) }
            val key = SCrypt.generate(password.toByteArray(), salt, n, 8, 1, 32)
            val ct = aead(true, key, nonce, entropy, keys.address.toByteArray())
            val o = JSONObject()
            o.put("version", 3)
            o.put("address", keys.address)
            o.put("pub", keys.pubHex)
            o.put("words", entropy.size * 3 / 4)
            o.put("nonce", nonce.hex())
            o.put("ct", ct.hex())
            o.put("kdf", JSONObject().put("name", "scrypt").put("n", n).put("r", 8).put("p", 1).put("salt", salt.hex()))
            return WalletFile(o)
        }

        fun load(f: File): WalletFile? = try {
            val o = JSONObject(f.readText())
            if (o.getInt("version") == 3 && Nyan.validAddress(o.getString("address"))) WalletFile(o) else null
        } catch (e: Exception) { null }

        private fun aead(encrypt: Boolean, key: ByteArray, nonce: ByteArray, data: ByteArray, aad: ByteArray): ByteArray {
            val c = ChaCha20Poly1305()
            c.init(encrypt, AEADParameters(KeyParameter(key), 128, nonce, aad))
            val out = ByteArray(c.getOutputSize(data.size))
            var len = c.processBytes(data, 0, data.size, out, 0)
            len += c.doFinal(out, len)
            return out.copyOf(len)
        }
    }
}
