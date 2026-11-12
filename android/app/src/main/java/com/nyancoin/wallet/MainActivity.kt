package com.nyancoin.wallet

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.animation.Crossfade
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AccountBalanceWallet
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.unit.dp
import com.nyancoin.wallet.ui.*
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    private val vm: AppViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(Nc.Bg.toArgb()),
            navigationBarStyle = SystemBarStyle.dark(Nc.Surface.toArgb()),
        )
        setContent { NyanTheme { App(vm) } }
    }
}

@Composable
private fun App(vm: AppViewModel) {
    Crossfade(vm.wallet == null, label = "root") { empty ->
        if (empty) Onboarding(vm) else Home(vm)
    }
}

@Composable
internal fun Home(vm: AppViewModel, startTab: Int = 0) {
    var tab by rememberSaveable { mutableIntStateOf(startTab) }
    val snackHost = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val snack: (String) -> Unit = { m -> scope.launch { snackHost.currentSnackbarData?.dismiss(); snackHost.showSnackbar(m) } }
    val mining by vm.miner.state.collectAsState()

    Scaffold(
        containerColor = Nc.Bg,
        snackbarHost = { SnackbarHost(snackHost) { Snackbar(it, containerColor = Nc.Surface2, contentColor = Nc.Text) } },
        bottomBar = {
            NavigationBar(containerColor = Nc.Surface, tonalElevation = 0.dp) {
                val items = listOf(
                    Triple("Wallet", Icons.Rounded.AccountBalanceWallet, 0),
                    Triple(if (mining.running) "Mining…" else "Mine", Icons.Rounded.Memory, 1),
                    Triple("Settings", Icons.Rounded.Settings, 2),
                )
                for ((label, icon, i) in items) NavigationBarItem(
                    selected = tab == i, onClick = { tab = i },
                    icon = { Icon(icon, label) }, label = { Text(label) },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = Nc.Pink, selectedTextColor = Nc.Pink,
                        indicatorColor = Nc.Pink.copy(alpha = 0.14f),
                        unselectedIconColor = Nc.Muted, unselectedTextColor = Nc.Muted,
                    ),
                )
            }
        },
    ) { pad ->
        Box(Modifier.padding(pad).consumeWindowInsets(pad).statusBarsPadding()) {
            Crossfade(tab, label = "tab") { t ->
                when (t) {
                    0 -> WalletScreen(vm, snack)
                    1 -> MineScreen(vm)
                    else -> SettingsScreen(vm, snack)
                }
            }
        }
    }
}
