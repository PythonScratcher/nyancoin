package com.nyancoin.wallet

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onRoot
import com.github.takahirom.roborazzi.captureRoboImage
import com.nyancoin.wallet.core.MinerState
import com.nyancoin.wallet.core.Nyan
import com.nyancoin.wallet.core.WalletFile
import com.nyancoin.wallet.ui.NyanTheme
import com.nyancoin.wallet.ui.Onboarding
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.io.File

/** Renders each screen as PNGs in build/shots so the look can be checked without a phone. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34], qualifiers = "w400dp-h860dp-xxhdpi")
class ScreenshotTest {
    @get:Rule val rule = createComposeRule()
    private val out = File(System.getProperty("user.dir"), "build/shots").apply { mkdirs() }

    private fun vm(withWallet: Boolean): AppViewModel {
        val app = RuntimeEnvironment.getApplication()
        val f = File(app.filesDir, "wallet.json")
        f.delete()
        if (withWallet) WalletFile.create(ByteArray(32) { it.toByte() }, "correct horse battery", n = 1024).save(f)
        return AppViewModel(app).also { it.demoMode = true }
    }

    private fun shot(name: String) = rule.onRoot().captureRoboImage(File(out, "$name.png").path)

    private val sample = listOf(
        Activity(Activity.Kind.RECEIVED, 2.5, "NYAN8352cf0b350b7389f59ce63b36a16eb8faef253029c1", 0, null, "ab", 0.0),
        Activity(Activity.Kind.REWARD, 1.0, null, 3, 1204, null, 0.0),
        Activity(Activity.Kind.SENT, -1.2501, "NYANe305634ff1babc194d403b7f2c81266a894ccd75ca41", 9, 1198, "cd", 0.0001),
        Activity(Activity.Kind.REWARD, 1.0, null, 40, 1167, null, 0.0),
        Activity(Activity.Kind.RECEIVED, 10.0, "NYAN0c1f9a2be7d4410c95e2b8a7f3d61c0b9e27aa14f2d8", 120, 1087, "ef", 0.0),
    )

    @Test fun welcome() {
        val v = vm(false)
        rule.setContent { NyanTheme { Onboarding(v) } }
        shot("1_welcome")
    }

    @Test fun wallet() {
        val v = vm(true)
        v.demo(14.75, 2.5, 1206, sample)
        rule.setContent { NyanTheme { Home(v, 0) } }
        shot("2_wallet")
    }

    @Test fun mine() {
        val v = vm(true)
        v.miner.demo(MinerState(running = true, status = "Mining block 1207", hashrate = 412_350.0, height = 1207, bits = 22, found = 3,
            log = listOf("17:42:10  ★ Found block 1204! +1.00 NYAN", "17:41:55  Block 1203: someone else was faster (stale).",
                "17:40:02  Connected. Mining with 7 cores.")))
        rule.mainClock.autoAdvance = false
        rule.setContent { NyanTheme { Home(v, 1) } }
        rule.mainClock.advanceTimeBy(700)
        shot("3_mine")
    }

    @Test fun settings() {
        val v = vm(true)
        rule.setContent { NyanTheme { Home(v, 2) } }
        shot("4_settings")
    }
}
