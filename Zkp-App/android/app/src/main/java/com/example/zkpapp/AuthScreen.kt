package com.example.zkpapp.ui

import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.zkpapp.AuthUiState
import kotlin.math.cos
import kotlin.math.sin
import kotlin.random.Random

// ─── Color Palette ────────────────────────────────────────────────────────────
private val SpaceBlack   = Color(0xFF020510)
private val DeepNavy     = Color(0xFF060D1F)
private val CyberCyan    = Color(0xFF00E5FF)
private val NeonBlue     = Color(0xFF1565FF)
private val PulseViolet  = Color(0xFF7B2FFF)
private val GlassWhite   = Color(0x14FFFFFF)
private val GlassBorder  = Color(0x30FFFFFF)
private val ErrorRed     = Color(0xFFFF3D5A)
private val WarnAmber    = Color(0xFFFFAB00)
private val TextPrimary  = Color(0xFFE8F4FF)
private val TextSecondary = Color(0xFF7A99C0)

// ─── Star data ────────────────────────────────────────────────────────────────
private data class Star(val x: Float, val y: Float, val radius: Float, val alpha: Float)

private fun generateStars(count: Int): List<Star> = List(count) {
    Star(
        x      = Random.nextFloat(),
        y      = Random.nextFloat(),
        radius = Random.nextFloat() * 1.8f + 0.3f,
        alpha  = Random.nextFloat() * 0.8f + 0.2f,
    )
}

// =========================================================
// MAIN SCREEN
// =========================================================
@Composable
fun AuthScreen(
    uiState: AuthUiState,
    isVaultExists: Boolean,
    onUnlockClick: () -> Unit,
    onCreateClick: () -> Unit,
    onRestoreClick: () -> Unit,
) {
    val stars = remember { generateStars(180) }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(SpaceBlack),
        contentAlignment = Alignment.Center
    ) {

        // ── Layer 1: Star field ──────────────────────────────
        StarField(stars = stars)

        // ── Layer 2: Deep glow orbs ──────────────────────────
        AmbientGlow()

        // ── Layer 3: Content ─────────────────────────────────
        Column(
            modifier            = Modifier
                .fillMaxSize()
                .padding(horizontal = 28.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {

            // Logo
            LionShieldLogo()

            Spacer(modifier = Modifier.height(20.dp))

            // Title
            Text(
                text       = "ZKP Identity",
                fontSize   = 34.sp,
                fontWeight = FontWeight.Bold,
                color      = TextPrimary,
                textAlign  = TextAlign.Center,
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text      = "Zero-Knowledge Login",
                fontSize  = 14.sp,
                color     = CyberCyan.copy(alpha = 0.8f),
                textAlign = TextAlign.Center,
            )
            Text(
                text      = "Private  ·  Secure  ·  Offline",
                fontSize  = 12.sp,
                color     = TextSecondary,
                textAlign = TextAlign.Center,
            )

            Spacer(modifier = Modifier.height(52.dp))

            // ── Main action area ──────────────────────────────
            if (isVaultExists) {
                // Vault exists → show fingerprint button
                BreathingFingerprintButton(onClick = onUnlockClick)
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text      = "Authenticate with Fingerprint",
                    fontSize  = 15.sp,
                    fontWeight = FontWeight.SemiBold,
                    color     = TextPrimary,
                )
                Text(
                    text    = "Scan & Unlock Securely",
                    fontSize = 12.sp,
                    color   = TextSecondary,
                )
            } else {
                // First time → Create / Restore
                GlassActionButton(
                    label      = "Create Identity",
                    gradient   = listOf(NeonBlue, CyberCyan),
                    onClick    = onCreateClick,
                )
                Spacer(modifier = Modifier.height(14.dp))
                GlassActionButton(
                    label      = "Restore Identity",
                    gradient   = listOf(PulseViolet, NeonBlue),
                    onClick    = onRestoreClick,
                )
            }

            Spacer(modifier = Modifier.height(36.dp))

            // ── Status message ────────────────────────────────
            StatusMessage(uiState = uiState)
        }
    }
}

// =========================================================
// STAR FIELD
// =========================================================
@Composable
private fun StarField(stars: List<Star>) {
    val infiniteTransition = rememberInfiniteTransition(label = "stars")
    val twinkle by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue  = 1f,
        animationSpec = infiniteRepeatable(
            animation  = tween(3000, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "twinkle",
    )

    Canvas(modifier = Modifier.fillMaxSize()) {
        stars.forEachIndexed { i, star ->
            val flicker = if (i % 3 == 0) twinkle else if (i % 3 == 1) 1f - twinkle else star.alpha
            drawCircle(
                color  = Color.White.copy(alpha = star.alpha * flicker.coerceIn(0.1f, 1f)),
                radius = star.radius,
                center = Offset(star.x * size.width, star.y * size.height),
            )
        }
    }
}

// =========================================================
// AMBIENT GLOW ORBS
// =========================================================
@Composable
private fun AmbientGlow() {
    val infiniteTransition = rememberInfiniteTransition(label = "glow")
    val pulse by infiniteTransition.animateFloat(
        initialValue  = 0.4f,
        targetValue   = 0.7f,
        animationSpec = infiniteRepeatable(
            animation  = tween(4000, easing = EaseInOutSine),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "pulse",
    )

    Canvas(modifier = Modifier.fillMaxSize()) {
        // Top-right cyan orb
        drawCircle(
            brush  = Brush.radialGradient(
                colors = listOf(CyberCyan.copy(alpha = pulse * 0.15f), Color.Transparent),
                center = Offset(size.width * 0.85f, size.height * 0.15f),
                radius = size.width * 0.6f,
            ),
            radius = size.width * 0.6f,
            center = Offset(size.width * 0.85f, size.height * 0.15f),
        )
        // Bottom-left violet orb
        drawCircle(
            brush  = Brush.radialGradient(
                colors = listOf(PulseViolet.copy(alpha = pulse * 0.12f), Color.Transparent),
                center = Offset(size.width * 0.15f, size.height * 0.85f),
                radius = size.width * 0.6f,
            ),
            radius = size.width * 0.6f,
            center = Offset(size.width * 0.15f, size.height * 0.85f),
        )
    }
}

// =========================================================
// LION SHIELD LOGO (Canvas drawn)
// =========================================================
@Composable
private fun LionShieldLogo() {
    val infiniteTransition = rememberInfiniteTransition(label = "logo")
    val cometAngle by infiniteTransition.animateFloat(
        initialValue  = 0f,
        targetValue   = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(6000, easing = LinearEasing),
        ),
        label = "comet",
    )

    Box(
        contentAlignment = Alignment.Center,
        modifier         = Modifier.size(90.dp),
    ) {
        // Rotating comet trail
        Canvas(modifier = Modifier.fillMaxSize()) {
            val cx     = size.width / 2f
            val cy     = size.height / 2f
            val radius = size.minDimension / 2.1f
            val rad    = Math.toRadians(cometAngle.toDouble())
            val x      = cx + radius * cos(rad).toFloat()
            val y      = cy + radius * sin(rad).toFloat()

            // Trail
            for (t in 0..20) {
                val trailRad   = Math.toRadians((cometAngle - t * 8.0))
                val tx         = cx + radius * cos(trailRad).toFloat()
                val ty         = cy + radius * sin(trailRad).toFloat()
                val trailAlpha = (1f - t / 20f) * 0.6f
                drawCircle(
                    color  = CyberCyan.copy(alpha = trailAlpha),
                    radius = 3f - t * 0.12f,
                    center = Offset(tx, ty),
                )
            }
            // Head
            drawCircle(color = Color.White, radius = 4f, center = Offset(x, y))
        }

        // Shield background
        Box(
            modifier = Modifier
                .size(72.dp)
                .clip(RoundedCornerShape(16.dp))
                .background(
                    Brush.verticalGradient(
                        colors = listOf(
                            Color(0xFF1A2744),
                            Color(0xFF0D1629),
                        )
                    )
                )
                .drawBehind {
                    drawRoundRect(
                        brush       = Brush.linearGradient(listOf(CyberCyan, PulseViolet)),
                        style       = Stroke(width = 1.5f),
                        cornerRadius = androidx.compose.ui.geometry.CornerRadius(16.dp.toPx()),
                    )
                },
            contentAlignment = Alignment.Center,
        ) {
            Text(text = "🦁", fontSize = 32.sp)
        }
    }
}

// =========================================================
// BREATHING FINGERPRINT BUTTON
// =========================================================
@Composable
fun BreathingFingerprintButton(onClick: () -> Unit) {
    val infiniteTransition = rememberInfiniteTransition(label = "fp")

    val scale by infiniteTransition.animateFloat(
        initialValue  = 0.93f,
        targetValue   = 1.07f,
        animationSpec = infiniteRepeatable(
            animation  = tween(2200, easing = EaseInOutSine),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "scale",
    )

    val glowAlpha by infiniteTransition.animateFloat(
        initialValue  = 0.25f,
        targetValue   = 0.75f,
        animationSpec = infiniteRepeatable(
            animation  = tween(2200, easing = EaseInOutSine),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "glow",
    )

    val ringScale by infiniteTransition.animateFloat(
        initialValue  = 0.7f,
        targetValue   = 1.5f,
        animationSpec = infiniteRepeatable(
            animation  = tween(2200, easing = EaseInOutSine),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "ring",
    )

    Box(
        contentAlignment = Alignment.Center,
        modifier         = Modifier.size(140.dp),
    ) {
        // Outer pulse ring
        Canvas(modifier = Modifier.fillMaxSize()) {
            val r = size.minDimension / 2f * ringScale
            drawCircle(
                color  = CyberCyan.copy(alpha = (1f - ringScale / 1.5f).coerceIn(0f, 0.3f)),
                radius = r,
                style  = Stroke(width = 1.5f),
            )
        }

        // Glow background
        Box(
            modifier = Modifier
                .size(110.dp)
                .scale(scale)
                .clip(CircleShape)
                .background(
                    Brush.radialGradient(
                        colors = listOf(
                            CyberCyan.copy(alpha = glowAlpha * 0.2f),
                            NeonBlue.copy(alpha  = glowAlpha * 0.1f),
                            Color.Transparent,
                        )
                    )
                )
                .drawBehind {
                    drawCircle(
                        brush = Brush.sweepGradient(
                            listOf(CyberCyan, PulseViolet, CyberCyan)
                        ),
                        style  = Stroke(width = 1.8f),
                        radius = size.minDimension / 2f - 1f,
                    )
                }
                .clickable(
                    interactionSource = remember { MutableInteractionSource() },
                    indication        = null,
                    onClick           = onClick,
                ),
            contentAlignment = Alignment.Center,
        ) {
            // Fingerprint icon (text fallback — replace with your ic_fingerprint)
            Text(
                text     = "🫆",
                fontSize = 44.sp,
                color    = CyberCyan.copy(alpha = glowAlpha + 0.2f),
            )
        }
    }
}

// =========================================================
// GLASS ACTION BUTTON (Create / Restore)
// =========================================================
@Composable
private fun GlassActionButton(
    label:   String,
    gradient: List<Color>,
    onClick: () -> Unit,
) {
    val interactionSource = remember { MutableInteractionSource() }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(56.dp)
            .clip(RoundedCornerShape(16.dp))
            .background(GlassWhite)
            .drawBehind {
                drawRoundRect(
                    brush        = Brush.linearGradient(gradient),
                    style        = Stroke(width = 1.5f),
                    cornerRadius = androidx.compose.ui.geometry.CornerRadius(16.dp.toPx()),
                )
            }
            .clickable(
                interactionSource = interactionSource,
                indication        = null,
                onClick           = onClick,
            ),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text       = label,
            fontSize   = 16.sp,
            fontWeight = FontWeight.SemiBold,
            color      = TextPrimary,
            textAlign  = TextAlign.Center,
        )
    }
}

// =========================================================
// STATUS MESSAGE
// =========================================================
@Composable
private fun StatusMessage(uiState: AuthUiState) {
    when (uiState) {
        is AuthUiState.Error -> {
            GlassStatusCard(
                message     = uiState.message,
                color       = ErrorRed,
                borderColor = ErrorRed.copy(alpha = 0.5f),
            )
        }
        is AuthUiState.RateLimited -> {
            GlassStatusCard(
                message     = "⛔  Too many failed attempts.\nTry again in ${uiState.waitSeconds}s...",
                color       = WarnAmber,
                borderColor = WarnAmber.copy(alpha = 0.5f),
            )
        }
        is AuthUiState.Loading -> {
            Text(
                text      = "⏳  Processing...",
                fontSize  = 14.sp,
                color     = CyberCyan,
                textAlign = TextAlign.Center,
            )
        }
        is AuthUiState.TamperDetected -> {
            GlassStatusCard(
                message     = "⚠️  Suspicious environment detected.\nProceed with caution.",
                color       = WarnAmber,
                borderColor = WarnAmber.copy(alpha = 0.5f),
            )
        }
        else -> { /* Idle / Success — no message */ }
    }
}

@Composable
private fun GlassStatusCard(
    message:     String,
    color:       Color,
    borderColor: Color,
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(color.copy(alpha = 0.08f))
            .drawBehind {
                drawRoundRect(
                    color        = borderColor,
                    style        = Stroke(width = 1f),
                    cornerRadius = androidx.compose.ui.geometry.CornerRadius(12.dp.toPx()),
                )
            }
            .padding(horizontal = 16.dp, vertical = 12.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text      = message,
            fontSize  = 13.sp,
            color     = color,
            textAlign = TextAlign.Center,
            lineHeight = 20.sp,
        )
    }
}