package com.nyancoin.wallet.ui

import android.app.Activity
import android.view.WindowManager
import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.nyancoin.wallet.AppViewModel
import com.nyancoin.wallet.core.Nyan
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private enum class Step { WELCOME, SHOW, VERIFY, RESTORE, PASSWORD }

/** Blocks screenshots / recent-apps previews while the recovery phrase is on screen. */
@Composable
fun SecureScreen() {
    val act = LocalContext.current as? Activity ?: return
    DisposableEffect(Unit) {
        act.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose { act.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE) }
    }
}

@Composable
fun Onboarding(vm: AppViewModel) {
    var step by remember { mutableStateOf(Step.WELCOME) }
    var entropy by remember { mutableStateOf<ByteArray?>(null) }
    var restoring by remember { mutableStateOf(false) }

    BackHandler(step != Step.WELCOME) {
        step = when (step) {
            Step.VERIFY -> Step.SHOW
            Step.PASSWORD -> if (restoring) Step.RESTORE else Step.VERIFY
            else -> Step.WELCOME
        }
    }

    Box(Modifier.fillMaxSize().background(Nc.Bg).systemBarsPadding().imePadding()) {
        AnimatedContent(step, transitionSpec = { fadeIn() togetherWith fadeOut() }, label = "onb") { s ->
            when (s) {
                Step.WELCOME -> Welcome(
                    onCreate = { restoring = false; entropy = Nyan.newEntropy(24); step = Step.SHOW },
                    onRestore = { restoring = true; step = Step.RESTORE },
                )
                Step.SHOW -> ShowPhrase(Nyan.entropyToWords(entropy!!), back = { step = Step.WELCOME }) { step = Step.VERIFY }
                Step.VERIFY -> VerifyPhrase(Nyan.entropyToWords(entropy!!), back = { step = Step.SHOW }) { step = Step.PASSWORD }
                Step.RESTORE -> RestorePhrase(back = { step = Step.WELCOME }) { entropy = it; step = Step.PASSWORD }
                Step.PASSWORD -> ChoosePassword(vm, entropy!!, back = { step = if (restoring) Step.RESTORE else Step.VERIFY })
            }
        }
    }
}

@Composable
private fun Header(title: String, sub: String, back: (() -> Unit)?) {
    Column(Modifier.fillMaxWidth().padding(top = 8.dp, bottom = 18.dp)) {
        if (back != null) IconButton(onClick = back, modifier = Modifier.offset(x = (-12).dp)) {
            Icon(Icons.AutoMirrored.Rounded.ArrowBack, "Back")
        }
        Text(title, style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(6.dp))
        Text(sub, color = Nc.Muted)
    }
}

@Composable
private fun Welcome(onCreate: () -> Unit, onRestore: () -> Unit) {
    Column(Modifier.fillMaxSize().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        Spacer(Modifier.weight(1f))
        CoinLogo(120.dp)
        Spacer(Modifier.height(28.dp))
        Text("NyanCoin", style = MaterialTheme.typography.displaySmall)
        Spacer(Modifier.height(8.dp))
        Text(
            "A tiny peer-to-peer coin.\nYour keys live only on this phone.",
            color = Nc.Muted, textAlign = TextAlign.Center,
        )
        Spacer(Modifier.weight(1.3f))
        BigButton("Create a new wallet", onCreate, Modifier.fillMaxWidth(), icon = Icons.Rounded.Add)
        Spacer(Modifier.height(12.dp))
        OutlinedButton(
            onClick = onRestore, modifier = Modifier.fillMaxWidth().height(56.dp), shape = RoundedCornerShape(18.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, Nc.Outline),
        ) {
            Icon(Icons.Rounded.Key, null, tint = Nc.Text); Spacer(Modifier.width(8.dp))
            Text("I have a recovery phrase", color = Nc.Text, style = MaterialTheme.typography.labelLarge)
        }
        Spacer(Modifier.height(12.dp))
    }
}

@Composable
fun WordGrid(words: List<String>) {
    val half = (words.size + 1) / 2
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        for (col in 0..1) Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            for (i in col * half until minOf(words.size, (col + 1) * half)) {
                Row(
                    Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(Nc.Surface2)
                        .padding(horizontal = 12.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("${i + 1}", color = Nc.Muted, fontFamily = Mono, fontSize = 12.sp, modifier = Modifier.width(24.dp))
                    Text(words[i], fontFamily = Mono, fontWeight = FontWeight.SemiBold)
                }
            }
        }
    }
}

@Composable
private fun Warn(text: String) {
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).background(Nc.Amber.copy(alpha = 0.12f)).padding(14.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Icon(Icons.Rounded.Warning, null, tint = Nc.Amber, modifier = Modifier.size(20.dp))
        Spacer(Modifier.width(10.dp))
        Text(text, color = Nc.Amber, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun ShowPhrase(words: List<String>, back: () -> Unit, next: () -> Unit) {
    SecureScreen()
    var ok by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().padding(horizontal = 20.dp)) {
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) {
            Header("Your recovery phrase", "Write these 24 words on paper, in order. They are the only way to get your coins back.", back)
            WordGrid(words)
            Spacer(Modifier.height(16.dp))
            Warn("Anyone who sees these words can take your coins. Never type them into a website or send them to anyone.")
            Spacer(Modifier.height(10.dp))
            Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)), verticalAlignment = Alignment.CenterVertically) {
                Checkbox(ok, { ok = it }, colors = CheckboxDefaults.colors(checkedColor = Nc.Pink))
                Text("I wrote all 24 words down", Modifier.padding(start = 4.dp))
            }
        }
        BigButton("Continue", next, Modifier.fillMaxWidth().padding(vertical = 16.dp), enabled = ok)
    }
}

@Composable
private fun VerifyPhrase(words: List<String>, back: () -> Unit, next: () -> Unit) {
    val picks = remember { (0 until words.size).shuffled().take(3).sorted() }
    val answers = remember { mutableStateListOf("", "", "") }
    val allOk = picks.indices.all { answers[it].trim().lowercase() == words[picks[it]] }
    Column(Modifier.fillMaxSize().padding(horizontal = 20.dp)) {
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) {
            Header("Check your backup", "Type the words you wrote down, so we know the paper copy is right.", back)
            picks.forEachIndexed { k, idx ->
                val v = answers[k].trim().lowercase()
                NcField(
                    answers[k], { answers[k] = it }, "Word #${idx + 1}", mono = true,
                    error = if (v.length >= words[idx].length && v != words[idx]) "That's not word #${idx + 1}" else null,
                    trailing = if (v == words[idx]) { { Icon(Icons.Rounded.CheckCircle, null, tint = Nc.Green) } } else null,
                )
                Spacer(Modifier.height(10.dp))
            }
        }
        BigButton("Continue", next, Modifier.fillMaxWidth().padding(vertical = 16.dp), enabled = allOk)
    }
}

@Composable
private fun RestorePhrase(back: () -> Unit, next: (ByteArray) -> Unit) {
    var text by remember { mutableStateOf("") }
    var result by remember { mutableStateOf<Pair<ByteArray?, String?>>(null to null) }
    var address by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(text) {
        address = null
        if (text.isBlank()) { result = null to null; return@LaunchedEffect }
        delay(350)
        result = try { Nyan.wordsToEntropy(text) to null } catch (e: Nyan.PhraseException) { null to e.message }
        result.first?.let { e -> address = withContext(Dispatchers.Default) { Nyan.Keys(Nyan.entropyToKeySeed(e)).address } }
    }
    Column(Modifier.fillMaxSize().padding(horizontal = 20.dp)) {
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) {
            Header("Restore wallet", "Enter your 12 or 24 words, separated by spaces. The first 4 letters of each word is enough.", back)
            SecureScreen()
            NcField(text, { text = it }, "Recovery phrase", mono = true, singleLine = false, minLines = 5, error = result.second)
            Spacer(Modifier.height(8.dp))
            address?.let {
                Panel {
                    SectionLabel("This phrase opens")
                    Spacer(Modifier.height(6.dp))
                    Text(it, fontFamily = Mono, fontSize = 13.sp, color = Nc.Green)
                }
            }
        }
        BigButton("Continue", { result.first?.let(next) }, Modifier.fillMaxWidth().padding(vertical = 16.dp), enabled = address != null)
    }
}

@Composable
private fun ChoosePassword(vm: AppViewModel, entropy: ByteArray, back: () -> Unit) {
    var pw by remember { mutableStateOf("") }
    var pw2 by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val tooShort = pw.isNotEmpty() && pw.length < 12
    val mismatch = pw2.isNotEmpty() && pw != pw2
    Column(Modifier.fillMaxSize().padding(horizontal = 20.dp)) {
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) {
            Header("Set a password", "It locks the wallet on this phone. You'll need it to send coins or view your phrase.", back)
            NcField(pw, { pw = it }, "Password (12+ characters)", password = true, error = if (tooShort) "Use at least 12 characters" else null)
            Spacer(Modifier.height(10.dp))
            NcField(pw2, { pw2 = it }, "Repeat password", password = true, error = if (mismatch) "Passwords don't match" else null)
            Spacer(Modifier.height(12.dp))
            Text("Forgot it later? No problem — restore from your recovery phrase and pick a new one.", color = Nc.Muted,
                style = MaterialTheme.typography.bodyMedium)
        }
        BigButton(
            "Create wallet", {
                busy = true
                scope.launch { vm.createWallet(entropy, pw) }
            },
            Modifier.fillMaxWidth().padding(vertical = 16.dp),
            enabled = pw.length >= 12 && pw == pw2, loading = busy,
        )
    }
}
