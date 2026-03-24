package com.example.zkpapp

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityOptionsCompat
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.math.cos
import kotlin.math.sin
import kotlin.random.Random

// ─── Colors ──────────────────────────────────────────────────
private val SpaceBlack   = Color(0xFF020510)
private val CyberCyan    = Color(0xFF00E5FF)
private val NeonBlue     = Color(0xFF1565FF)
private val PulseViolet  = Color(0xFF7B2FFF)
private val NeonGreen    = Color(0xFF00FF88)
private val NeonOrange   = Color(0xFFFF6B00)
private val GlassWhite   = Color(0x12FFFFFF)
private val TextPrimary  = Color(0xFFE8F4FF)
private val TextSecondary= Color(0xFF7A99C0)

private data class Star(val x: Float, val y: Float, val r: Float, val alpha: Float)

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 🛡️ Anti-Screenshot
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        setContent {
            // Identity state — drives lock icon + status bar
            val hasPassport = IdentityStorage.hasRealPassport() &&
                              IdentityStorage.hasPersistentIdentity(this)
            val hasDevice   = DeviceTierGate.isDeviceRegistered(this)
            val isUnlocked  = hasPassport || hasDevice

            MainDashboard(
                isWebLoginUnlocked = isUnlocked,
                hasRealPassport    = hasPassport,
                onScanQr = {
                    when {
                        // PATH 1 — Real NFC passport ✅
                        hasPassport -> {
                            launchActivitySmoothly(
                                Intent(this, QrLoginActivity::class.java)
                            )
                        }
                        // PATH 2 — Tier 3 registered ✅
                        hasDevice -> {
                            launchActivitySmoothly(
                                Intent(this, QrLoginActivity::class.java)
                            )
                        }
                        // LOCKED ❌
                        else -> showUnlockDialog()
                    }
                },
                onScanPassport = {
                    // 🎯 FIX APPLIED HERE: PassportActivity -> TierSelectionActivity
                    launchActivitySmoothly(Intent(this, TierSelectionActivity::class.java)) 
                },
                onOfflineIdentity = {
                    if (IdentityStorage.hasIdentity()) {
                        launchActivitySmoothly(Intent(this, OfflineMenuActivity::class.java)) // 👈
                    } else {
                        Toast.makeText(this, "⚠️ Please Scan Passport First!", Toast.LENGTH_SHORT).show()
                    }
                },
                onTestProof = {
                    launchActivitySmoothly(Intent(this, TestProofActivity::class.java)) // 👈
                }
            )
        }
    }

    // 👈 Ye function add kiya hai fade in/out animations ke liye
    private fun launchActivitySmoothly(intent: Intent) {
        val options = ActivityOptionsCompat.makeCustomAnimation(
            this,
            android.R.anim.fade_in,
            android.R.anim.fade_out
        )
        startActivity(intent, options.toBundle())
    }

    // ── Unlock Dialog — shown when no proof exists ────────────────────────────
    private fun showUnlockDialog() {
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("🔒 Identity Required")
            .setMessage("Web Login requires a verified identity.\n\nChoose how to register:")
            .setPositiveButton("🛂 Scan Passport") { _, _ ->
                // Real NFC passport → MAXIMUM trust
                launchActivitySmoothly(Intent(this, TierSelectionActivity::class.java))
            }
            .setNeutralButton("📱 Device Proof") { _, _ ->
                // Fingerprint only → BASIC trust
                launchActivitySmoothly(Intent(this, TierSelectionActivity::class.java))
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
}

// =========================================================
// MAIN DASHBOARD
// =========================================================
@Composable
fun MainDashboard(
    isWebLoginUnlocked: Boolean = false,
    hasRealPassport:    Boolean = false,
    onScanQr:           () -> Unit,
    onScanPassport:     () -> Unit,
    onOfflineIdentity:  () -> Unit,
    onTestProof:        () -> Unit,
) {
    val stars = remember { List(160) {
        Star(Random.nextFloat(), Random.nextFloat(),
        Random.nextFloat() * 1.6f + 0.3f, Random.nextFloat() * 0.8f + 0.2f)
    }}

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(SpaceBlack),
        contentAlignment = Alignment.Center,
    ) {
        // Star field
        StarField(stars)

        // Ambient glow orbs
        AmbientOrbs()

        // Content
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 24.dp)
                .padding(top = 52.dp, bottom = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {

            // ── Header ───────────────────────────────────────
            DashboardHeader()

            Spacer(Modifier.height(40.dp))

            // ── Status bar ───────────────────────────────────
            StatusBar()

            Spacer(Modifier.height(36.dp))

            // ── Action cards ─────────────────────────────────
            DashboardCard(
                icon        = if (isWebLoginUnlocked) "⬡" else "🔒",
                title       = "SCAN QR",
                subtitle    = if (isWebLoginUnlocked)
                                  if (hasRealPassport) "Passport · MAXIMUM Trust"
                                  else "Device · BASIC Trust"
                              else "Register identity to unlock",
                gradient    = if (isWebLoginUnlocked)
                                  listOf(NeonBlue, CyberCyan)
                              else listOf(Color(0xFF374151), Color(0xFF4B5563)),
                onClick     = onScanQr,
            )
            Spacer(Modifier.height(14.dp))

            DashboardCard(
                icon        = "◈",
                title       = "SCAN PASSPORT",
                subtitle    = "Create Identity",
                gradient    = listOf(NeonOrange, Color(0xFFFFD600)),
                onClick     = onScanPassport,
            )
            Spacer(Modifier.height(14.dp))

            DashboardCard(
                icon        = "◎",
                title       = "OFFLINE IDENTITY",
                subtitle    = "Transmit · Verify",
                gradient    = listOf(NeonGreen, CyberCyan),
                onClick     = onOfflineIdentity,
            )
            Spacer(Modifier.height(14.dp))

            DashboardCard(
                icon        = "⬟",
                title       = "TEST PROOF",
                subtitle    = "Benchmark ZK Circuit",
                gradient    = listOf(PulseViolet, NeonBlue),
                onClick     = onTestProof,
            )

            Spacer(Modifier.weight(1f))

            // ── Footer ───────────────────────────────────────
            Text(
                text      = "ZERO · KNOWLEDGE · OFFLINE",
                fontSize  = 10.sp,
                color     = TextSecondary.copy(alpha = 0.5f),
                letterSpacing = 3.sp,
                textAlign = TextAlign.Center,
            )
        }
    }
}

// =========================================================
// HEADER
// =========================================================
@Composable
private fun DashboardHeader() {
    val infiniteTransition = rememberInfiniteTransition(label = "header")
    val pulse by infiniteTransition.animateFloat(
        initialValue  = 0.6f,
        targetValue   = 1f,
        animationSpec = infiniteRepeatable(
            animation  = tween(2000, easing = EaseInOutSine),
            repeatMode = RepeatMode.Reverse,
        ), label = "pulse"
    )

    Column(horizontalAlignment = Alignment.CenterHorizontally) {

        // Hexagon logo
        Box(contentAlignment = Alignment.Center, modifier = Modifier.size(80.dp)) {
            Canvas(modifier = Modifier.fillMaxSize()) {
                val cx = size.width / 2f
                val cy = size.height / 2f
                val r  = size.minDimension / 2.2f

                // Outer hex glow
                val hexPath = Path().apply {
                    for (i in 0..5) {
                        val angle = Math.toRadians((60 * i - 30).toDouble())
                        val x = cx + r * cos(angle).toFloat()
                        val y = cy + r * sin(angle).toFloat()
                        if (i == 0) moveTo(x, y) else lineTo(x, y)
                    }
                    close()
                }
                drawPath(
                    path  = hexPath,
                    brush = Brush.linearGradient(listOf(CyberCyan, PulseViolet)),
                    style = Stroke(width = 2f),
                )
                // Inner hex fill
                val hexInner = Path().apply {
                    for (i in 0..5) {
                        val angle = Math.toRadians((60 * i - 30).toDouble())
                        val x = cx + (r * 0.85f) * cos(angle).toFloat()
                        val y = cy + (r * 0.85f) * sin(angle).toFloat()
                        if (i == 0) moveTo(x, y) else lineTo(x, y)
                    }
                    close()
                }
                drawPath(
                    path  = hexInner,
                    brush = Brush.radialGradient(
                        colors = listOf(
                            CyberCyan.copy(alpha = pulse * 0.15f),
                            PulseViolet.copy(alpha = pulse * 0.05f),
                        ),
                        center = Offset(cx, cy),
                        radius = r,
                    ),
                )
            }
            // Shield icon
            Text(text = "🛡", fontSize = 28.sp)
        }

        Spacer(Modifier.height(16.dp))

        // Title
        Text(
            text       = "ZKP IDENTITY",
            fontSize   = 28.sp,
            fontWeight = FontWeight.Black,
            color      = TextPrimary,
            letterSpacing = 4.sp,
            textAlign  = TextAlign.Center,
        )
        Spacer(Modifier.height(4.dp))
        Text(
            text      = "Sovereign Identity Protocol",
            fontSize  = 12.sp,
            color     = CyberCyan.copy(alpha = 0.7f),
            letterSpacing = 1.sp,
            textAlign = TextAlign.Center,
        )
    }
}

// =========================================================
// STATUS BAR
// =========================================================
@Composable
private fun StatusBar(
    isUnlocked:     Boolean = false,
    hasRealPassport:Boolean = false,
) {
    val infiniteTransition = rememberInfiniteTransition(label = "status")
    val blink by infiniteTransition.animateFloat(
        initialValue  = 0.3f,
        targetValue   = 1f,
        animationSpec = infiniteRepeatable(
            animation  = tween(1000, easing = EaseInOutSine),
            repeatMode = RepeatMode.Reverse,
        ), label = "blink"
    )

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(GlassWhite)
            .padding(horizontal = 16.dp, vertical = 10.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // Online indicator
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Canvas(modifier = Modifier.size(8.dp)) {
                drawCircle(color = NeonGreen.copy(alpha = blink))
            }
            Text(text = "SYSTEM ONLINE", fontSize = 10.sp, color = NeonGreen, letterSpacing = 1.sp)
        }

        // Security level
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(text = "ZK-PROOF", fontSize = 10.sp, color = CyberCyan, letterSpacing = 1.sp)
            Canvas(modifier = Modifier.size(8.dp)) {
                drawCircle(color = CyberCyan.copy(alpha = blink))
            }
        }
    }
}

// =========================================================
// DASHBOARD CARD
// =========================================================
@Composable
private fun DashboardCard(
    icon:     String,
    title:    String,
    subtitle: String,
    gradient: List<Color>,
    onClick:  () -> Unit,
) {
    val interactionSource = remember { MutableInteractionSource() }

    val pressed by interactionSource.collectIsPressedAsState()

    val scale by animateFloatAsState(
        targetValue   = if (pressed) 0.97f else 1f,
        animationSpec = spring(dampingRatio = Spring.DampingRatioMediumBouncy),
        label         = "scale"
    )

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(72.dp)
            .scale(scale)
            .clip(RoundedCornerShape(14.dp))
            .background(GlassWhite)
            .drawBehind {
                // Gradient border
                drawRoundRect(
                    brush        = Brush.linearGradient(gradient),
                    style        = Stroke(width = 1.5f),
                    cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx()),
                )
                // Left accent bar
                drawRoundRect(
                    brush        = Brush.linearGradient(gradient),
                    topLeft      = Offset(0f, size.height * 0.2f),
                    size         = androidx.compose.ui.geometry.Size(3f, size.height * 0.6f),
                    cornerRadius = androidx.compose.ui.geometry.CornerRadius(4f),
                )
            }
            .clickable(
                interactionSource = interactionSource,
                indication        = null,
                onClick           = onClick
            )
            .padding(horizontal = 20.dp),
        contentAlignment = Alignment.CenterStart,
    ) {
        Row(
            verticalAlignment     = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            // Icon box
            Box(
                modifier         = Modifier
                    .size(42.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(
                        Brush.linearGradient(
                            listOf(gradient[0].copy(alpha = 0.2f), gradient[1].copy(alpha = 0.1f))
                        )
                    ),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text     = icon,
                    fontSize = 20.sp,
                    color    = gradient[0],
                )
            }

            // Text
            Column {
                Text(
                    text          = title,
                    fontSize      = 15.sp,
                    fontWeight    = FontWeight.Bold,
                    color         = TextPrimary,
                    letterSpacing = 2.sp,
                )
                Text(
                    text      = subtitle,
                    fontSize  = 11.sp,
                    color     = TextSecondary,
                    letterSpacing = 0.5.sp,
                )
            }

            Spacer(Modifier.weight(1f))

            // Arrow
            Text(
                text  = "›",
                fontSize = 22.sp,
                color = gradient[0].copy(alpha = 0.7f),
            )
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
        initialValue  = 0f,
        targetValue   = 1f,
        animationSpec = infiniteRepeatable(
            animation  = tween(3000, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse,
        ), label = "twinkle"
    )
    Canvas(modifier = Modifier.fillMaxSize()) {
        stars.forEachIndexed { i, s ->
            val flicker = if (i % 3 == 0) twinkle else if (i % 3 == 1) 1f - twinkle else s.alpha
            drawCircle(
                color  = Color.White.copy(alpha = s.alpha * flicker.coerceIn(0.1f, 1f)),
                radius = s.r,
                center = Offset(s.x * size.width, s.y * size.height),
            )
        }
    }
}

// =========================================================
// AMBIENT ORBS
// =========================================================
@Composable
private fun AmbientOrbs() {
    val infiniteTransition = rememberInfiniteTransition(label = "orbs")
    val pulse by infiniteTransition.animateFloat(
        initialValue  = 0.3f,
        targetValue   = 0.6f,
        animationSpec = infiniteRepeatable(
            animation  = tween(4000, easing = EaseInOutSine),
            repeatMode = RepeatMode.Reverse,
        ), label = "orb"
    )
    Canvas(modifier = Modifier.fillMaxSize()) {
        drawCircle(
            brush  = Brush.radialGradient(
                colors = listOf(CyberCyan.copy(alpha = pulse * 0.12f), Color.Transparent),
                center = Offset(size.width * 0.9f, size.height * 0.1f),
                radius = size.width * 0.55f,
            ),
            radius = size.width * 0.55f,
            center = Offset(size.width * 0.9f, size.height * 0.1f),
        )
        drawCircle(
            brush  = Brush.radialGradient(
                colors = listOf(PulseViolet.copy(alpha = pulse * 0.1f), Color.Transparent),
                center = Offset(size.width * 0.1f, size.height * 0.9f),
                radius = size.width * 0.55f,
            ),
            radius = size.width * 0.55f,
            center = Offset(size.width * 0.1f, size.height * 0.9f),
        )
    }   
}