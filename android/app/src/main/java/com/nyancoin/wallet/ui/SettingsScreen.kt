package com.nyancoin.wallet.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ChevronRight
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.nyancoin.wallet.AppViewModel
import com.nyancoin.wallet.BuildConfig
import com.nyancoin.wallet.core.Nyan
import com.nyancoin.wallet.core.WalletFile
import kotlinx.coroutines.launch

@Composable
fun SettingsScreen(vm: AppViewModel, snack: (String) -> Unit) {
    var nodeText by remember(vm.nodeUrl) { mutableStateOf(vm.nodeUrl) }
    var nodeErr by remember { mutableStateOf<String?>(null) }
    var saving by remember { mutableStateOf(false) }
    var askPhrase by remember { mutableStateOf(false) }
    var phrase by remember { mutableStateOf<List<String>?>(null) }
    var askRemove by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 18.dp)) {
        Text("Settings", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.padding(vertical = 18.dp))

        SectionLabel("Node", Modifier.padding(start = 4.dp, bottom = 8.dp))
        Panel(Modifier.fillMaxWidth()) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Rounded.Dns, null, tint = Nc.Violet)
                Spacer(Modifier.width(10.dp))
                Text("Which node the app talks to", color = Nc.Muted, fontSize = 13.sp)
            }
            Spacer(Modifier.height(12.dp))
            NcField(nodeText, { nodeText = it; nodeErr = null }, "https://host:port#pin", mono = true, singleLine = false, error = nodeErr)
            Text(
                "The part after # pins the node's key, so nobody can pretend to be it. Without a pin, the first key seen is remembered.",
                color = Nc.Muted, fontSize = 12.sp,
            )
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedButton(
                    onClick = { nodeText = Nyan.DEFAULT_NODE; nodeErr = null },
                    shape = RoundedCornerShape(14.dp), modifier = Modifier.weight(1f),
                ) { Text("Default", color = Nc.Text) }
                Button(
                    onClick = {
                        saving = true
                        scope.launch {
                            nodeErr = vm.setNode(nodeText); saving = false
                            if (nodeErr == null) snack("Connected to node")
                        }
                    },
                    enabled = !saving && nodeText.trim() != vm.nodeUrl,
                    shape = RoundedCornerShape(14.dp), modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = Nc.Pink),
                ) {
                    if (saving) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = Color.White)
                    else Text("Test & save")
                }
            }
        }

        Spacer(Modifier.height(22.dp))
        SectionLabel("Wallet", Modifier.padding(start = 4.dp, bottom = 8.dp))
        Panel(Modifier.fillMaxWidth(), padding = 6.dp) {
            SettingRow(Icons.Rounded.Key, "Show recovery phrase", "Needs your password", Nc.Pink) { askPhrase = true }
            HorizontalDivider(color = Nc.Outline, modifier = Modifier.padding(horizontal = 12.dp))
            SettingRow(Icons.Rounded.Delete, "Remove wallet from this phone", "You can restore it with the phrase", Nc.Red) { askRemove = true }
        }

        Spacer(Modifier.height(22.dp))
        SectionLabel("About", Modifier.padding(start = 4.dp, bottom = 8.dp))
        Panel(Modifier.fillMaxWidth()) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                CoinLogo(44.dp)
                Spacer(Modifier.width(14.dp))
                Column {
                    Text("NyanCoin Wallet", fontWeight = FontWeight.SemiBold)
                    Text("v${BuildConfig.VERSION_NAME} · chain ${Nyan.CHAIN_ID}", color = Nc.Muted, fontSize = 13.sp)
                }
            }
            Spacer(Modifier.height(10.dp))
            Text("Rules fingerprint", color = Nc.Muted, fontSize = 12.sp)
            Text(Nyan.RULES.take(16), fontFamily = Mono, fontSize = 13.sp)
        }
        Spacer(Modifier.height(30.dp))
    }

    if (askPhrase) PasswordDialog("Show recovery phrase", "Make sure nobody is looking at your screen.", "Show", { askPhrase = false }) { pw ->
        try { phrase = vm.revealPhrase(pw); askPhrase = false; null } catch (e: WalletFile.WrongPassword) { "Wrong password" }
    }
    phrase?.let { words ->
        SecureScreen()
        AlertDialog(
            onDismissRequest = { phrase = null }, containerColor = Nc.Surface,
            title = { Text("Recovery phrase") },
            text = { Column(Modifier.verticalScroll(rememberScrollState())) { WordGrid(words) } },
            confirmButton = { TextButton(onClick = { phrase = null }) { Text("Hide", color = Nc.Pink) } },
        )
    }
    if (askRemove) {
        var sure by remember { mutableStateOf(false) }
        AlertDialog(
            onDismissRequest = { askRemove = false }, containerColor = Nc.Surface,
            icon = { Icon(Icons.Rounded.Warning, null, tint = Nc.Red) },
            title = { Text("Remove wallet?") },
            text = {
                Column {
                    Text("This deletes the wallet from this phone. Your coins stay on the chain, but you can ONLY get them back with your recovery phrase.", color = Nc.Muted)
                    Spacer(Modifier.height(10.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(sure, { sure = it }, colors = CheckboxDefaults.colors(checkedColor = Nc.Red))
                        Text("I have my recovery phrase")
                    }
                }
            },
            confirmButton = {
                Button(onClick = { askRemove = false; vm.removeWallet() }, enabled = sure,
                    colors = ButtonDefaults.buttonColors(containerColor = Nc.Red)) { Text("Remove") }
            },
            dismissButton = { TextButton(onClick = { askRemove = false }) { Text("Cancel", color = Nc.Muted) } },
        )
    }
}

@Composable
private fun SettingRow(icon: ImageVector, title: String, sub: String, tint: Color, onClick: () -> Unit) {
    Surface(onClick = onClick, color = Color.Transparent, shape = RoundedCornerShape(16.dp)) {
        Row(Modifier.fillMaxWidth().padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, null, tint = tint)
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                Text(sub, color = Nc.Muted, fontSize = 13.sp)
            }
            Icon(Icons.Rounded.ChevronRight, null, tint = Nc.Muted)
        }
    }
}
