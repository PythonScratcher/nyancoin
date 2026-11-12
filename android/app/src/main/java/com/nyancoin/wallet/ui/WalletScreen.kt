package com.nyancoin.wallet.ui

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.nyancoin.wallet.Activity
import com.nyancoin.wallet.AppViewModel
import com.nyancoin.wallet.core.NodeException
import com.nyancoin.wallet.core.Nyan
import com.nyancoin.wallet.core.WalletFile
import java.math.BigDecimal

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WalletScreen(vm: AppViewModel, snack: (String) -> Unit) {
    val w = vm.wallet ?: return
    var sheet by remember { mutableStateOf<String?>(null) }
    val clip = LocalClipboardManager.current

    PullToRefreshBox(isRefreshing = vm.refreshing, onRefresh = { vm.refresh() }, modifier = Modifier.fillMaxSize()) {
        LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(start = 18.dp, end = 18.dp, bottom = 24.dp)) {
            item { TopRow(vm) }
            item {
                BalanceCard(vm, onSend = { sheet = "send" }, onReceive = { sheet = "receive" })
            }
            item {
                Spacer(Modifier.height(14.dp))
                Surface(
                    onClick = { clip.setText(AnnotatedString(w.address)); snack("Address copied") },
                    shape = RoundedCornerShape(16.dp), color = Nc.Surface,
                ) {
                    Row(Modifier.fillMaxWidth().padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            SectionLabel("Your address")
                            Spacer(Modifier.height(4.dp))
                            Text(w.address, fontFamily = Mono, fontSize = 12.5.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        }
                        Icon(Icons.Rounded.ContentCopy, "Copy", tint = Nc.Muted, modifier = Modifier.padding(start = 10.dp).size(20.dp))
                    }
                }
            }
            item {
                Row(Modifier.fillMaxWidth().padding(top = 26.dp, bottom = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text("Activity", style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
                    vm.chainHeight?.let { Text("block #${"%,d".format(it)}", color = Nc.Muted, fontSize = 12.sp, fontFamily = Mono) }
                }
            }
            if (vm.activity.isEmpty()) item {
                Panel(Modifier.fillMaxWidth()) {
                    Centered(
                        if (vm.balance == null) "Loading…" else "Nothing here yet.\nReceive some NYAN or start mining!",
                        modifier = Modifier.padding(vertical = 18.dp),
                    )
                }
            }
            items(vm.activity) { ActivityRow(it) }
        }
    }

    when (sheet) {
        "send" -> SendSheet(vm, onDone = { sheet = null; if (it != null) snack(it) })
        "receive" -> ReceiveSheet(w.address, snack) { sheet = null }
    }
}

@Composable
private fun TopRow(vm: AppViewModel) {
    Row(Modifier.fillMaxWidth().padding(vertical = 14.dp), verticalAlignment = Alignment.CenterVertically) {
        CoinLogo(38.dp)
        Spacer(Modifier.width(12.dp))
        Text("NyanCoin", style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
        val ok = vm.nodeError == null && vm.chainHeight != null
        Row(
            Modifier.clip(RoundedCornerShape(50)).background(Nc.Surface).padding(horizontal = 10.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(Modifier.size(8.dp).clip(CircleShape).background(when {
                vm.nodeError != null -> Nc.Red; ok -> Nc.Green; else -> Nc.Amber
            }))
            Spacer(Modifier.width(6.dp))
            Text(when { vm.nodeError != null -> "Offline"; ok -> "Synced"; else -> "Connecting" }, fontSize = 12.sp, color = Nc.Muted)
        }
    }
}

@Composable
private fun BalanceCard(vm: AppViewModel, onSend: () -> Unit, onReceive: () -> Unit) {
    Column(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(28.dp)).background(Nc.Hero).padding(22.dp).animateContentSize(),
    ) {
        Text("Balance", color = Color.White.copy(alpha = 0.8f), style = MaterialTheme.typography.labelMedium)
        Spacer(Modifier.height(6.dp))
        Row(verticalAlignment = Alignment.Bottom) {
            Text(
                vm.balance?.let { nyan(it) } ?: "—", color = Color.White,
                style = MaterialTheme.typography.displaySmall, maxLines = 1,
                modifier = Modifier.weight(1f, fill = false),
            )
            Text(" NYAN", color = Color.White.copy(alpha = 0.85f), fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(bottom = 6.dp))
        }
        if (vm.pendingIn > 0 || vm.pendingOut > 0) {
            Spacer(Modifier.height(4.dp))
            val parts = buildList {
                if (vm.pendingIn > 0) add("+${nyan(vm.pendingIn)} incoming")
                if (vm.pendingOut > 0) add("−${nyan(vm.pendingOut)} outgoing")
            }
            Text(parts.joinToString(" · ") + " (pending)", color = Color.White.copy(alpha = 0.85f), fontSize = 13.sp)
        }
        vm.nodeError?.let {
            Spacer(Modifier.height(6.dp))
            Text(it, color = Color.White, fontSize = 13.sp)
        }
        Spacer(Modifier.height(20.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            SoftButton("Send", Icons.Rounded.ArrowUpward, onSend, Modifier.weight(1f), tint = Color.White)
            SoftButton("Receive", Icons.Rounded.ArrowDownward, onReceive, Modifier.weight(1f), tint = Color.White)
        }
    }
}

@Composable
private fun ActivityRow(a: Activity) {
    val (icon, color, title) = when (a.kind) {
        Activity.Kind.RECEIVED -> Triple(Icons.Rounded.SouthWest, Nc.Green, "Received")
        Activity.Kind.SENT -> Triple(Icons.Rounded.NorthEast, Nc.Pink, "Sent")
        Activity.Kind.SELF -> Triple(Icons.Rounded.Sync, Nc.Muted, "Sent to yourself")
        Activity.Kind.REWARD -> Triple(Icons.Rounded.Bolt, Nc.Amber, "Mining reward")
    }
    Row(Modifier.fillMaxWidth().padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(44.dp).clip(CircleShape).background(color.copy(alpha = 0.14f)), contentAlignment = Alignment.Center) {
            Icon(icon, null, tint = color, modifier = Modifier.size(22.dp))
        }
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            val sub = buildString {
                when (a.kind) {
                    Activity.Kind.RECEIVED -> append("from ${Nyan.shortAddress(a.other ?: "")}")
                    Activity.Kind.SENT -> append("to ${Nyan.shortAddress(a.other ?: "")}")
                    else -> a.height?.let { append("block #$it") }
                }
            }
            Text(sub, color = Nc.Muted, fontSize = 12.5.sp, fontFamily = Mono, maxLines = 1)
        }
        Column(horizontalAlignment = Alignment.End) {
            val sign = if (a.amount >= 0) "+" else "−"
            Text(
                "$sign${nyan(kotlin.math.abs(a.amount))}",
                color = if (a.amount >= 0) Nc.Green else Nc.Text, fontWeight = FontWeight.SemiBold, fontFamily = Mono,
            )
            if (a.confirmations == 0) Text("pending", color = Nc.Amber, fontSize = 12.sp)
            else Text(if (a.confirmations >= 6) "confirmed" else "${a.confirmations} conf", color = Nc.Muted, fontSize = 12.sp)
        }
    }
}

// ---------------------------------------------------------------------------------------- receive

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ReceiveSheet(address: String, snack: (String) -> Unit, onClose: () -> Unit) {
    val clip = LocalClipboardManager.current
    val ctx = LocalContext.current
    ModalBottomSheet(onDismissRequest = onClose, containerColor = Nc.Surface, sheetState = rememberModalBottomSheetState(true)) {
        Column(Modifier.fillMaxWidth().padding(horizontal = 24.dp).padding(bottom = 28.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Text("Receive NYAN", style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.height(6.dp))
            Text("Share this address or let someone scan the code.", color = Nc.Muted, textAlign = TextAlign.Center)
            Spacer(Modifier.height(22.dp))
            QrCode(address, Modifier.size(240.dp))
            Spacer(Modifier.height(20.dp))
            Text(
                address.chunked(4).joinToString(" "), fontFamily = Mono, fontSize = 14.sp, textAlign = TextAlign.Center,
                modifier = Modifier.clip(RoundedCornerShape(14.dp)).background(Nc.Surface2).padding(14.dp),
            )
            Spacer(Modifier.height(20.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedButton(
                    onClick = { clip.setText(AnnotatedString(address)); snack("Address copied") },
                    modifier = Modifier.weight(1f).height(52.dp), shape = RoundedCornerShape(16.dp),
                ) { Icon(Icons.Rounded.ContentCopy, null); Spacer(Modifier.width(8.dp)); Text("Copy") }
                Button(
                    onClick = { share(ctx, address) }, modifier = Modifier.weight(1f).height(52.dp),
                    shape = RoundedCornerShape(16.dp), colors = ButtonDefaults.buttonColors(containerColor = Nc.Pink),
                ) { Icon(Icons.Rounded.Share, null); Spacer(Modifier.width(8.dp)); Text("Share") }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------- send

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SendSheet(vm: AppViewModel, onDone: (String?) -> Unit) {
    val clip = LocalClipboardManager.current
    var to by remember { mutableStateOf("") }
    var amount by remember { mutableStateOf("") }
    var fee by remember { mutableStateOf("0.0001") }
    var feeOpen by remember { mutableStateOf(false) }
    var confirm by remember { mutableStateOf(false) }
    var sentTx by remember { mutableStateOf<String?>(null) }

    val toTrim = to.trim()
    val toErr = when {
        toTrim.isEmpty() -> null
        !Nyan.validAddress(toTrim) -> "That isn't a valid NYAN address (check for typos)"
        else -> null
    }
    val amt = Nyan.parseAmount(amount)
    val feeU = if (fee.trim() == "0") 0L else Nyan.parseAmount(fee)
    val bal = vm.balance?.let { BigDecimal(it.toString()).movePointRight(8).toLong() }
    val total = if (amt != null && feeU != null) amt + feeU else null
    val amtErr = when {
        amount.isBlank() -> null
        amt == null -> "Enter an amount like 1.5"
        bal != null && total != null && total > bal -> "More than your balance (${nyan(vm.balance!!)})"
        else -> null
    }
    val ready = toTrim.isNotEmpty() && toErr == null && amt != null && amtErr == null && feeU != null

    ModalBottomSheet(onDismissRequest = { onDone(null) }, containerColor = Nc.Surface, sheetState = rememberModalBottomSheetState(true)) {
        Column(
            Modifier.fillMaxWidth().padding(horizontal = 22.dp).padding(bottom = 24.dp).imePadding().verticalScroll(rememberScrollState()),
        ) {
            if (sentTx != null) {
                Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                    Spacer(Modifier.height(10.dp))
                    Box(Modifier.size(84.dp).clip(CircleShape).background(Nc.Green.copy(alpha = 0.15f)), contentAlignment = Alignment.Center) {
                        Icon(Icons.Rounded.Check, null, tint = Nc.Green, modifier = Modifier.size(44.dp))
                    }
                    Spacer(Modifier.height(16.dp))
                    Text("Sent!", style = MaterialTheme.typography.headlineSmall)
                    Spacer(Modifier.height(6.dp))
                    Text("${nyan(amt!! / 1e8)} NYAN is on its way. It confirms in the next block (~10 s).", color = Nc.Muted, textAlign = TextAlign.Center)
                    Spacer(Modifier.height(14.dp))
                    Text(sentTx!!, fontFamily = Mono, fontSize = 11.sp, color = Nc.Muted, textAlign = TextAlign.Center)
                    Spacer(Modifier.height(20.dp))
                    BigButton("Done", { onDone(null) }, Modifier.fillMaxWidth())
                }
                return@Column
            }
            Text("Send NYAN", style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.height(16.dp))
            NcField(
                to, { to = it.replace("\n", "").replace(" ", "") }, "To address", mono = true, error = toErr,
                trailing = {
                    IconButton(onClick = { clip.getText()?.text?.let { to = it.trim() } }) { Icon(Icons.Rounded.ContentPaste, "Paste") }
                },
            )
            Spacer(Modifier.height(8.dp))
            NcField(
                amount, { amount = it.replace(',', '.') }, "Amount (NYAN)", keyboard = KeyboardType.Decimal, error = amtErr,
                trailing = {
                    TextButton(onClick = {
                        if (bal != null && feeU != null && bal > feeU)
                            amount = BigDecimal(bal - feeU).movePointLeft(8).stripTrailingZeros().toPlainString()
                    }) { Text("MAX", color = Nc.Pink) }
                },
            )
            Spacer(Modifier.height(4.dp))
            Row(
                Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).clickableNoRipple { feeOpen = !feeOpen }.padding(vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("Network fee: ${fee.ifBlank { "?" }} NYAN", color = Nc.Muted, modifier = Modifier.weight(1f))
                Icon(if (feeOpen) Icons.Rounded.ExpandLess else Icons.Rounded.ExpandMore, null, tint = Nc.Muted)
            }
            if (feeOpen) {
                Text(
                    "The fee goes to whoever mines the block. When blocks are full, miners pick the highest fees first. " +
                        "0.0001 is plenty right now.",
                    color = Nc.Muted, fontSize = 13.sp,
                )
                Spacer(Modifier.height(8.dp))
                NcField(fee, { fee = it.replace(',', '.') }, "Fee (NYAN)", keyboard = KeyboardType.Decimal,
                    error = if (feeU == null) "Enter a fee like 0.0001 (or 0)" else null)
            }
            Spacer(Modifier.height(16.dp))
            if (ready) Panel(Modifier.fillMaxWidth(), padding = 16.dp) {
                SummaryRow("Amount", "${nyan(amt!! / 1e8)} NYAN")
                SummaryRow("Fee", "${nyan(feeU!! / 1e8)} NYAN")
                HorizontalDivider(Modifier.padding(vertical = 8.dp), color = Nc.Outline)
                SummaryRow("Total", "${nyan(total!! / 1e8)} NYAN", bold = true)
                SummaryRow("To", Nyan.shortAddress(toTrim))
            }
            Spacer(Modifier.height(16.dp))
            BigButton("Review & send", { confirm = true }, Modifier.fillMaxWidth(), enabled = ready, icon = Icons.Rounded.Send)
        }
    }

    if (confirm) PasswordDialog(
        title = "Confirm payment",
        body = "Send ${nyan(amt!! / 1e8)} NYAN to ${Nyan.shortAddress(toTrim)}? Payments can't be undone.",
        confirm = "Send", onDismiss = { confirm = false },
    ) { pw ->
        try {
            val keys = vm.unlock(pw)
            sentTx = vm.send(keys, toTrim, amt, feeU!!)
            confirm = false
            null
        } catch (e: WalletFile.WrongPassword) { "Wrong password" }
        catch (e: NodeException) { e.message ?: "The node refused it" }
    }
}

@Composable
private fun SummaryRow(k: String, v: String, bold: Boolean = false) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
        Text(k, color = Nc.Muted, modifier = Modifier.weight(1f))
        Text(v, fontFamily = Mono, fontWeight = if (bold) FontWeight.Bold else FontWeight.Normal)
    }
}
