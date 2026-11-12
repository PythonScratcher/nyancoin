package com.nyancoin.wallet.ui

import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Visibility
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import kotlinx.coroutines.launch
import java.text.DecimalFormat
import java.text.DecimalFormatSymbols
import java.util.Locale

private val amountFmt = DecimalFormat("#,##0.########", DecimalFormatSymbols(Locale.US))
fun nyan(v: Double): String = amountFmt.format(v)

/** Cute logo: a pink coin with a cat face drawn in text. */
@Composable
fun CoinLogo(size: Dp = 40.dp) {
    Box(
        Modifier.size(size).clip(CircleShape).background(Nc.Hero),
        contentAlignment = Alignment.Center,
    ) {
        Text("=^･ω･^=", color = Color.White, fontSize = (size.value / 4.2f).sp, fontWeight = FontWeight.Bold, maxLines = 1)
    }
}

@Composable
fun Panel(modifier: Modifier = Modifier, padding: Dp = 18.dp, content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier
            .clip(RoundedCornerShape(22.dp))
            .background(Nc.Surface)
            .border(1.dp, Nc.Outline.copy(alpha = 0.6f), RoundedCornerShape(22.dp))
            .padding(padding),
        content = content,
    )
}

@Composable
fun SectionLabel(text: String, modifier: Modifier = Modifier) =
    Text(text.uppercase(), modifier = modifier, style = MaterialTheme.typography.labelMedium, color = Nc.Muted)

@Composable
fun BigButton(
    text: String, onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true,
    loading: Boolean = false, icon: ImageVector? = null, brush: Brush = Nc.Hero,
) {
    val active = enabled && !loading
    Box(
        modifier
            .height(56.dp)
            .clip(RoundedCornerShape(18.dp))
            .background(if (active) brush else Brush.linearGradient(listOf(Nc.Surface2, Nc.Surface2)))
            .then(if (active) Modifier.clickableNoRipple(onClick) else Modifier),
        contentAlignment = Alignment.Center,
    ) {
        if (loading) CircularProgressIndicator(Modifier.size(24.dp), color = Color.White, strokeWidth = 2.5.dp)
        else Row(verticalAlignment = Alignment.CenterVertically) {
            if (icon != null) { Icon(icon, null, tint = if (active) Color.White else Nc.Muted); Spacer(Modifier.width(8.dp)) }
            Text(text, color = if (active) Color.White else Nc.Muted, style = MaterialTheme.typography.labelLarge)
        }
    }
}

@Composable
fun SoftButton(text: String, icon: ImageVector?, onClick: () -> Unit, modifier: Modifier = Modifier, tint: Color = Nc.Text) {
    Surface(
        onClick = onClick, modifier = modifier.height(52.dp), shape = RoundedCornerShape(16.dp),
        color = Color.White.copy(alpha = 0.14f), contentColor = tint,
    ) {
        Row(Modifier.fillMaxSize(), horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
            if (icon != null) { Icon(icon, null, Modifier.size(20.dp)); Spacer(Modifier.width(8.dp)) }
            Text(text, style = MaterialTheme.typography.labelLarge)
        }
    }
}

fun Modifier.clickableNoRipple(onClick: () -> Unit): Modifier = this.clickable(onClick = onClick)

@Composable
fun NcField(
    value: String, onChange: (String) -> Unit, label: String, modifier: Modifier = Modifier,
    mono: Boolean = false, error: String? = null, singleLine: Boolean = true, minLines: Int = 1,
    keyboard: KeyboardType = KeyboardType.Text, trailing: @Composable (() -> Unit)? = null,
    password: Boolean = false,
) {
    var show by remember { mutableStateOf(false) }
    OutlinedTextField(
        value = value, onValueChange = onChange, label = { Text(label) }, modifier = modifier.fillMaxWidth(),
        singleLine = singleLine, minLines = minLines, isError = error != null,
        supportingText = error?.let { { Text(it) } },
        textStyle = LocalTextStyle.current.copy(fontFamily = if (mono) Mono else null),
        keyboardOptions = KeyboardOptions(keyboardType = if (password) KeyboardType.Password else keyboard, autoCorrectEnabled = false),
        visualTransformation = if (password && !show) PasswordVisualTransformation() else VisualTransformation.None,
        trailingIcon = if (password) {
            { IconButton(onClick = { show = !show }) { Icon(if (show) Icons.Rounded.VisibilityOff else Icons.Rounded.Visibility, null) } }
        } else trailing,
        shape = RoundedCornerShape(16.dp),
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = Nc.Pink, unfocusedBorderColor = Nc.Outline,
            focusedContainerColor = Nc.Surface, unfocusedContainerColor = Nc.Surface,
            cursorColor = Nc.Pink, focusedLabelColor = Nc.Pink,
        ),
    )
}

/**
 * Asks for the wallet password and runs [action] with it.
 * [action] returns an error message to show, or null when done.
 */
@Composable
fun PasswordDialog(title: String, body: String, confirm: String, onDismiss: () -> Unit, action: suspend (String) -> String?) {
    var pw by remember { mutableStateOf("") }
    var err by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        containerColor = Nc.Surface,
        icon = { Icon(Icons.Rounded.Lock, null, tint = Nc.Pink) },
        title = { Text(title) },
        text = {
            Column {
                Text(body, color = Nc.Muted)
                Spacer(Modifier.height(14.dp))
                NcField(pw, { pw = it; err = null }, "Wallet password", password = true, error = err)
            }
        },
        confirmButton = {
            Button(
                onClick = { busy = true; scope.launch { err = action(pw); busy = false } },
                enabled = pw.isNotEmpty() && !busy,
                colors = ButtonDefaults.buttonColors(containerColor = Nc.Pink),
            ) {
                if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = Color.White)
                else Text(confirm)
            }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !busy) { Text("Cancel", color = Nc.Muted) } },
    )
}

fun qrBitmap(text: String, px: Int = 640): ImageBitmap {
    val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, px, px, mapOf(EncodeHintType.MARGIN to 1))
    val pixels = IntArray(px * px) { i -> if (m[i % px, i / px]) 0xFF0D0E13.toInt() else 0xFFFFFFFF.toInt() }
    return Bitmap.createBitmap(pixels, px, px, Bitmap.Config.ARGB_8888).asImageBitmap()
}

@Composable
fun QrCode(text: String, modifier: Modifier = Modifier) {
    val bmp = remember(text) { qrBitmap(text) }
    Box(modifier.clip(RoundedCornerShape(20.dp)).background(Color.White).padding(12.dp)) {
        Image(bmp, "QR code", Modifier.fillMaxSize())
    }
}

fun share(ctx: Context, text: String) {
    val i = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text)
    ctx.startActivity(Intent.createChooser(i, "Share address"))
}

@Composable
fun Centered(text: String, color: Color = Nc.Muted, modifier: Modifier = Modifier) =
    Text(text, modifier.fillMaxWidth(), color = color, textAlign = TextAlign.Center, style = MaterialTheme.typography.bodyMedium)
