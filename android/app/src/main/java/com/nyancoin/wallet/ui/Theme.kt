package com.nyancoin.wallet.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

object Nc {
    val Bg = Color(0xFF0D0E13)
    val Surface = Color(0xFF161821)
    val Surface2 = Color(0xFF1F2230)
    val Outline = Color(0xFF2C3042)
    val Text = Color(0xFFECEEF6)
    val Muted = Color(0xFF8E94AA)
    val Pink = Color(0xFFFF7AC6)
    val Violet = Color(0xFF8C7BFF)
    val Green = Color(0xFF5FE0A6)
    val Amber = Color(0xFFFFC56B)
    val Red = Color(0xFFFF6B7A)
    val Hero = Brush.linearGradient(listOf(Color(0xFFFF6FB8), Color(0xFF9B6BFF), Color(0xFF5A7CFF)))
}

val Mono = FontFamily.Monospace

private val scheme = darkColorScheme(
    primary = Nc.Pink, onPrimary = Color(0xFF2B0A1E),
    secondary = Nc.Violet, onSecondary = Color.White,
    tertiary = Nc.Green,
    background = Nc.Bg, onBackground = Nc.Text,
    surface = Nc.Surface, onSurface = Nc.Text,
    surfaceVariant = Nc.Surface2, onSurfaceVariant = Nc.Muted,
    surfaceContainer = Nc.Surface, surfaceContainerHigh = Nc.Surface2, surfaceContainerHighest = Nc.Surface2,
    outline = Nc.Outline, outlineVariant = Nc.Outline,
    error = Nc.Red,
)

private val type = Typography(
    displaySmall = TextStyle(fontSize = 34.sp, fontWeight = FontWeight.Bold, letterSpacing = (-0.5).sp),
    headlineSmall = TextStyle(fontSize = 24.sp, fontWeight = FontWeight.Bold),
    titleLarge = TextStyle(fontSize = 20.sp, fontWeight = FontWeight.SemiBold),
    titleMedium = TextStyle(fontSize = 16.sp, fontWeight = FontWeight.SemiBold),
    bodyLarge = TextStyle(fontSize = 16.sp),
    bodyMedium = TextStyle(fontSize = 14.sp),
    labelLarge = TextStyle(fontSize = 15.sp, fontWeight = FontWeight.SemiBold),
    labelMedium = TextStyle(fontSize = 12.sp, fontWeight = FontWeight.Medium, letterSpacing = 0.4.sp),
)

@Composable
fun NyanTheme(content: @Composable () -> Unit) = MaterialTheme(colorScheme = scheme, typography = type) {
    androidx.compose.runtime.CompositionLocalProvider(androidx.compose.material3.LocalContentColor provides Nc.Text, content = content)
}
