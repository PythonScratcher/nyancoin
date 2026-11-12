package com.nyancoin.wallet.ui

import android.app.Activity
import android.view.WindowManager
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.PlayArrow
import androidx.compose.material.icons.rounded.Stop
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.nyancoin.wallet.AppViewModel
import kotlin.math.pow

fun hashrate(h: Double): String = when {
    h >= 1e6 -> "%.2f MH/s".format(h / 1e6)
    h >= 1e3 -> "%.1f kH/s".format(h / 1e3)
    else -> "%.0f H/s".format(h)
}

fun duration(s: Double): String = when {
    s.isInfinite() || s.isNaN() -> "—"
    s < 90 -> "%.0f s".format(s)
    s < 5400 -> "%.0f min".format(s / 60)
    s < 172800 -> "%.1f h".format(s / 3600)
    else -> "%.1f days".format(s / 86400)
}

@Composable
fun MineScreen(vm: AppViewModel) {
    val st by vm.miner.state.collectAsState()
    val act = LocalContext.current as? Activity
    val keep = st.running && vm.keepAwake
    DisposableEffect(keep) {
        if (keep) act?.window?.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        onDispose { act?.window?.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON) }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 18.dp)) {
        Text("Mine", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.padding(vertical = 18.dp))

        // ---- hero dial
        Box(Modifier.fillMaxWidth().height(250.dp), contentAlignment = Alignment.Center) {
            Dial(st.running)
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(if (st.running) hashrate(st.hashrate) else "Idle", style = MaterialTheme.typography.displaySmall)
                Spacer(Modifier.height(4.dp))
                Text(st.status, color = Nc.Muted, fontSize = 14.sp)
            }
        }

        Spacer(Modifier.height(8.dp))
        if (st.running) BigButton("Stop mining", { vm.miner.stop() }, Modifier.fillMaxWidth(), icon = Icons.Rounded.Stop,
            brush = Brush.linearGradient(listOf(Nc.Surface2, Nc.Surface2)))
        else BigButton("Start mining", { vm.startMining() }, Modifier.fillMaxWidth(), icon = Icons.Rounded.PlayArrow,
            enabled = vm.wallet != null && !st.status.startsWith("Stopping"))

        Spacer(Modifier.height(16.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Stat("Blocks found", "${st.found}", Modifier.weight(1f), Nc.Green)
            Stat("Block height", if (st.height > 0) "%,d".format(st.height) else "—", Modifier.weight(1f))
        }
        Spacer(Modifier.height(12.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Stat("Difficulty", if (st.bits > 0) "${st.bits} bits" else "—", Modifier.weight(1f))
            val est = if (st.running && st.hashrate > 0 && st.bits > 0) 2.0.pow(st.bits) / st.hashrate else Double.NaN
            Stat("Your time / block", duration(est), Modifier.weight(1f), Nc.Amber)
        }

        Spacer(Modifier.height(16.dp))
        Panel(Modifier.fillMaxWidth()) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("CPU threads", style = MaterialTheme.typography.titleMedium)
                    Text("More threads = faster, warmer phone", color = Nc.Muted, fontSize = 13.sp)
                }
                Text("${vm.threads} / ${vm.maxThreads}", fontFamily = Mono, fontWeight = FontWeight.Bold)
            }
            if (vm.maxThreads > 1) Slider(
                value = vm.threads.toFloat(), onValueChange = { vm.changeThreads(it.toInt()) },
                valueRange = 1f..vm.maxThreads.toFloat(), steps = (vm.maxThreads - 2).coerceAtLeast(0),
                enabled = !st.running,
                colors = SliderDefaults.colors(thumbColor = Nc.Pink, activeTrackColor = Nc.Pink, inactiveTrackColor = Nc.Surface2),
            )
            HorizontalDivider(Modifier.padding(vertical = 8.dp), color = Nc.Outline)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Keep screen on", style = MaterialTheme.typography.titleMedium)
                    Text("Android slows apps once the screen is off", color = Nc.Muted, fontSize = 13.sp)
                }
                Switch(vm.keepAwake, { vm.changeKeepAwake(it) }, colors = SwitchDefaults.colors(checkedTrackColor = Nc.Pink))
            }
        }

        Spacer(Modifier.height(16.dp))
        Panel(Modifier.fillMaxWidth(), padding = 14.dp) {
            SectionLabel("Log")
            Spacer(Modifier.height(8.dp))
            if (st.log.isEmpty()) Text("Nothing yet.", color = Nc.Muted, fontSize = 13.sp)
            st.log.take(25).forEach { line ->
                val c = when {
                    "★" in line -> Nc.Green
                    "⚠" in line || "faster" in line -> Nc.Amber
                    else -> Nc.Muted
                }
                Text(line, fontFamily = Mono, fontSize = 11.5.sp, color = c, lineHeight = 16.sp)
            }
        }
        Spacer(Modifier.height(10.dp))
        Text(
            "Phones are slow next to PCs, so blocks may take a while once the network grows. Mining pays to your own address.",
            color = Nc.Muted, fontSize = 12.sp, modifier = Modifier.padding(horizontal = 4.dp, vertical = 8.dp),
        )
        Spacer(Modifier.height(16.dp))
    }
}

@Composable
private fun Stat(label: String, value: String, modifier: Modifier, color: Color = Nc.Text) {
    Panel(modifier, padding = 16.dp) {
        SectionLabel(label)
        Spacer(Modifier.height(6.dp))
        Text(value, style = MaterialTheme.typography.titleLarge, color = color, fontFamily = Mono, maxLines = 1)
    }
}

@Composable
private fun Dial(running: Boolean) {
    val t = rememberInfiniteTransition(label = "dial")
    val angle by t.animateFloat(0f, 360f, infiniteRepeatable(tween(2200, easing = LinearEasing)), label = "a")
    val pulse by t.animateFloat(0.55f, 1f, infiniteRepeatable(tween(1100), RepeatMode.Reverse), label = "p")
    Canvas(Modifier.size(230.dp)) {
        val stroke = 14.dp.toPx()
        val inset = stroke / 2
        val sz = Size(size.width - stroke, size.height - stroke)
        drawArc(Nc.Surface2, 0f, 360f, false, Offset(inset, inset), sz, style = Stroke(stroke))
        if (running) {
            drawArc(
                Brush.sweepGradient(listOf(Color.Transparent, Nc.Violet, Nc.Pink, Color.Transparent)),
                angle, 220f, false, Offset(inset, inset), sz, alpha = pulse, style = Stroke(stroke, cap = StrokeCap.Round),
            )
        }
    }
}
