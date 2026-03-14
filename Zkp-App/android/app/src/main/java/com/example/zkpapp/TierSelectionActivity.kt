package com.example.zkpapp

import android.content.Intent
import android.graphics.*
import android.graphics.drawable.*
import android.os.Build
import android.os.Bundle
import android.os.VibrationEffect
import android.os.Vibrator
import android.view.*
import android.view.animation.*
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.cardview.widget.CardView

class TierSelectionActivity : AppCompatActivity() {

    private val colorBg       = Color.parseColor("#020810")
    private val colorBg2      = Color.parseColor("#050f1e")
    private val colorCyan     = Color.parseColor("#00f5ff")
    private val colorGreen    = Color.parseColor("#00ff88")
    private val colorRed      = Color.parseColor("#ff3366")
    private val colorGold     = Color.parseColor("#ffd700")
    private val colorPurple   = Color.parseColor("#9d50bb")
    private val colorBorder   = Color.parseColor("#1a3a4a")
    private val colorCardBg   = Color.parseColor("#070e1a")

    private var selectedTier   = -1
    private val tierCards      = mutableListOf<CardView>()
    private val tierIndicators = mutableListOf<TextView>()

    // lateinit — initialized inside buildUI() BEFORE buildTierCard() calls
    private lateinit var btnContinue: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        window.statusBarColor     = colorBg
        window.navigationBarColor = colorBg
        buildUI()
    }

    private fun buildUI() {
        val root = FrameLayout(this).apply { setBackgroundColor(colorBg) }
        val scroll = ScrollView(this).apply {
            layoutParams   = FrameLayout.LayoutParams(MATCH, MATCH)
            overScrollMode = View.OVER_SCROLL_NEVER
        }
        val container = LinearLayout(this).apply {
            orientation  = LinearLayout.VERTICAL
            layoutParams = FrameLayout.LayoutParams(MATCH, WRAP)
        }

        // ✅ FIX: Build continue button FIRST (before tier cards)
        // so btnContinue is fully configured when selectTier() is called
        val continueView = buildContinueButton()

        container.addView(buildHeader())
        container.addView(buildSubtitle())
        container.addView(spacer(8))
        container.addView(buildTierCard(1, "🛂", "TIER 1 — PASSPORT",
            "ICAO 9303 · NFC CHIP · BAC AUTH", "MAXIMUM TRUST",
            colorGreen, Color.parseColor("#003322"), colorGreen,
            listOf("🌍" to "International Passport + NFC",
                   "🔐" to "Govt RSA chip authentication",
                   "✅" to "Full identity + age + nationality",
                   "🏦" to "Financial & government portals",
                   "🔒" to "All claim types unlocked"), "RECOMMENDED"))
        container.addView(spacer(12))
        container.addView(buildTierCard(2, "🪪", "TIER 2 — NATIONAL ID",
            "CNIC / AADHAAR / ANY NFC ID CARD", "HIGH TRUST",
            colorCyan, Color.parseColor("#002233"), colorCyan,
            listOf("🌐" to "Any country's NFC ID card",
                   "🔐" to "Chip authentication verified",
                   "✅" to "Age + nationality confirmed",
                   "🛒" to "E-commerce & most websites",
                   "⚠️" to "No international financial"), "HIGH SECURITY"))
        container.addView(spacer(12))
        container.addView(buildTierCard(3, "📱", "TIER 3 — DEVICE ONLY",
            "BIOMETRIC · HARDWARE BACKED", "BASIC TRUST",
            colorGold, Color.parseColor("#332200"), colorGold,
            listOf("👆" to "Fingerprint / face biometric",
                   "📱" to "Hardware-backed device proof",
                   "🔑" to "Unique nullifier (no duplicates)",
                   "🤖" to "Captcha + password replacement",
                   "❌" to "Identity unverified"), "BASIC"))
        container.addView(spacer(20))
        container.addView(continueView)  // Add pre-built button view
        container.addView(spacer(36))

        scroll.addView(container)
        root.addView(scroll)
        setContentView(root)
    }

    private fun buildHeader(): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(px(20), px(20), px(20), px(16))
            gravity     = Gravity.CENTER_VERTICAL
            setBackgroundColor(colorBg)
        }
        val back = TextView(this).apply {
            text      = "←"; textSize = 20f
            setTextColor(colorCyan)
            setPadding(px(12), px(10), px(12), px(10))
            background = cyberBorder(colorBorder, 12f)
            setOnClickListener { finish() }
        }
        val titleBlock = LinearLayout(this).apply {
            orientation  = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, WRAP, 1f).apply { setMargins(px(14), 0, 0, 0) }
        }
        titleBlock.addView(TextView(this).apply {
            text = "CREATE IDENTITY"; textSize = 14f
            setTextColor(colorCyan); letterSpacing = 0.15f; typeface = Typeface.DEFAULT_BOLD
        })
        titleBlock.addView(TextView(this).apply {
            text = "SELECT YOUR TRUST TIER"; textSize = 9f
            setTextColor(Color.parseColor("#447788")); letterSpacing = 0.1f
        })
        val shield = TextView(this).apply {
            text = "🔐"; textSize = 20f
            setPadding(px(10), px(8), px(10), px(8))
            background = cyberBorder(Color.parseColor("#003322"), 10f)
        }
        row.addView(back); row.addView(titleBlock); row.addView(shield)
        val divider = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(MATCH, 1)
            setBackgroundColor(colorBorder)
        }
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(row); addView(divider)
        }
    }

    private fun buildSubtitle(): View {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(px(20), px(16), px(20), px(4))
            addView(TextView(this@TierSelectionActivity).apply {
                text = "Choose your identity level. Higher tier = more trust, more features."
                textSize = 11f; setTextColor(Color.parseColor("#4a7a8a"))
                letterSpacing = 0.03f; lineHeight = (textSize * 1.7f).toInt()
            })
            addView(spacer(10))
            val strip = LinearLayout(this@TierSelectionActivity).apply {
                orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
            }
            listOf("🟢 Passport" to colorGreen, " > " to Color.parseColor("#334455"),
                   "🔵 National ID" to colorCyan, " > " to Color.parseColor("#334455"),
                   "🟡 Device" to colorGold).forEach { (label, color) ->
                strip.addView(TextView(this@TierSelectionActivity).apply {
                    text = label; textSize = 9f; setTextColor(color)
                    letterSpacing = 0.05f; typeface = Typeface.DEFAULT_BOLD
                })
            }
            addView(strip)
        }
    }

    private fun buildTierCard(
        tier: Int, icon: String, title: String, subtitle: String,
        trustLabel: String, trustColor: Int, borderColor: Int, glowColor: Int,
        features: List<Pair<String, String>>, tagText: String
    ): View {
        val wrapper = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(px(16), 0, px(16), 0)
        }
        val card = CardView(this).apply {
            radius = px(16).toFloat(); cardElevation = 0f
            setCardBackgroundColor(colorCardBg)
            layoutParams = LinearLayout.LayoutParams(MATCH, WRAP)
        }
        tierCards.add(card)

        val inner = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }

        // Header
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(px(16), px(14), px(16), px(14)); gravity = Gravity.CENTER_VERTICAL
            background = GradientDrawable().apply {
                shape = GradientDrawable.RECTANGLE
                colors = intArrayOf(adjustAlpha(glowColor, 0.07f), Color.TRANSPARENT)
                orientation = GradientDrawable.Orientation.LEFT_RIGHT
                cornerRadii = floatArrayOf(px(16).toFloat(), px(16).toFloat(), 0f, 0f, 0f, 0f, px(16).toFloat(), px(16).toFloat())
            }
        }
        val iconView = TextView(this).apply {
            text = icon; textSize = 22f; gravity = Gravity.CENTER
            setPadding(px(10), px(8), px(10), px(8))
            background = GradientDrawable().apply {
                shape = GradientDrawable.OVAL
                setColor(adjustAlpha(glowColor, 0.12f)); setStroke(1, adjustAlpha(glowColor, 0.4f))
            }
            layoutParams = LinearLayout.LayoutParams(px(48), px(48)).apply { setMargins(0, 0, px(14), 0) }
        }
        val titleBlock = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, WRAP, 1f)
        }
        titleBlock.addView(TextView(this).apply {
            text = title; textSize = 12f; setTextColor(Color.WHITE)
            typeface = Typeface.DEFAULT_BOLD; letterSpacing = 0.1f
        })
        titleBlock.addView(TextView(this).apply {
            text = subtitle; textSize = 8f
            setTextColor(Color.parseColor("#447788")); letterSpacing = 0.08f
        })
        val trustBadge = TextView(this).apply {
            text = trustLabel; textSize = 8f; setPadding(px(8), px(5), px(8), px(5))
            setTextColor(trustColor); typeface = Typeface.DEFAULT_BOLD
            background = GradientDrawable().apply {
                shape = GradientDrawable.RECTANGLE; cornerRadius = px(20).toFloat()
                setColor(adjustAlpha(trustColor, 0.1f)); setStroke(1, adjustAlpha(trustColor, 0.35f))
            }
        }
        header.addView(iconView); header.addView(titleBlock); header.addView(trustBadge)

        // Divider
        val divider = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(MATCH, 1); setBackgroundColor(colorBorder)
        }

        // Features
        val featureList = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(px(16), px(12), px(16), px(14))
        }
        features.forEach { (emoji, text) ->
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
                layoutParams = LinearLayout.LayoutParams(MATCH, WRAP).apply { setMargins(0, 0, 0, px(6)) }
            }
            row.addView(TextView(this).apply {
                this.text = emoji; textSize = 12f; layoutParams = LinearLayout.LayoutParams(px(28), WRAP)
            })
            row.addView(TextView(this).apply {
                this.text = text; textSize = 11f
                setTextColor(Color.parseColor("#8aaabb")); letterSpacing = 0.02f
            })
            featureList.addView(row)
        }

        // Footer
        val footer = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(px(16), px(10), px(16), px(12)); gravity = Gravity.CENTER_VERTICAL
            background = GradientDrawable().apply {
                shape = GradientDrawable.RECTANGLE; setColor(Color.parseColor("#04090f"))
                cornerRadii = floatArrayOf(0f, 0f, 0f, 0f, px(16).toFloat(), px(16).toFloat(), px(16).toFloat(), px(16).toFloat())
            }
        }
        val tagTv = TextView(this).apply {
            text = tagText; textSize = 8f; setTextColor(trustColor)
            typeface = Typeface.DEFAULT_BOLD; letterSpacing = 0.15f
            layoutParams = LinearLayout.LayoutParams(0, WRAP, 1f)
        }
        val selectIndicator = TextView(this).apply {
            text = "TAP TO SELECT"; textSize = 8f
            setTextColor(Color.parseColor("#334455")); letterSpacing = 0.1f
        }
        tierIndicators.add(selectIndicator)
        footer.addView(tagTv); footer.addView(selectIndicator)

        inner.addView(header); inner.addView(divider)
        inner.addView(featureList); inner.addView(footer)
        card.addView(inner); wrapper.addView(card)

        card.setOnClickListener { selectTier(tier, card, glowColor, trustColor, selectIndicator) }

        card.alpha = 0f; card.translationY = px(20).toFloat()
        card.animate().alpha(1f).translationY(0f)
            .setStartDelay((tier * 120).toLong()).setDuration(400)
            .setInterpolator(DecelerateInterpolator()).start()

        return wrapper
    }

    private fun selectTier(
        tier: Int, selectedCard: CardView,
        glowColor: Int, trustColor: Int, selectIndicator: TextView
    ) {
        selectedTier = tier

        try {
            val v = getSystemService(VIBRATOR_SERVICE) as Vibrator
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                v.vibrate(VibrationEffect.createOneShot(60, VibrationEffect.DEFAULT_AMPLITUDE))
            else @Suppress("DEPRECATION") v.vibrate(60)
        } catch (_: Exception) {}

        // Reset all cards
        tierCards.forEach { card ->
            card.foreground = null; card.setCardBackgroundColor(colorCardBg)
        }
        tierIndicators.forEach { indicator ->
            indicator.text = "TAP TO SELECT"; indicator.setTextColor(Color.parseColor("#334455"))
        }

        // Highlight selected
        selectedCard.foreground = GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE; cornerRadius = px(16).toFloat()
            setColor(Color.TRANSPARENT); setStroke(px(2), glowColor)
        }
        selectIndicator.text = "✅ SELECTED"; selectIndicator.setTextColor(trustColor)

        // ✅ FIX: btnContinue already initialized — directly update
        btnContinue.isEnabled = true
        btnContinue.alpha     = 1f
        btnContinue.text      = when (tier) {
            1 -> "CONTINUE WITH PASSPORT  →"
            2 -> "CONTINUE WITH NATIONAL ID  →"
            3 -> "CONTINUE WITH DEVICE  →"
            else -> "CONTINUE  →"
        }
        btnContinue.background = GradientDrawable(
            GradientDrawable.Orientation.LEFT_RIGHT,
            when (tier) {
                1    -> intArrayOf(Color.parseColor("#006633"), Color.parseColor("#00cc66"))
                2    -> intArrayOf(Color.parseColor("#005577"), Color.parseColor("#00bcd4"))
                3    -> intArrayOf(Color.parseColor("#554400"), Color.parseColor("#cc9900"))
                else -> intArrayOf(Color.parseColor("#0055cc"), Color.parseColor("#00bcd4"))
            }
        ).apply { cornerRadius = px(14).toFloat() }

        btnContinue.animate().scaleX(1.02f).scaleY(1.02f).setDuration(100).withEndAction {
            btnContinue.animate().scaleX(1f).scaleY(1f).setDuration(100).start()
        }.start()
    }

    private fun buildContinueButton(): View {
        val wrapper = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(px(16), 0, px(16), 0)
        }
        // ✅ Assign btnContinue HERE — this is the only place it's initialized
        btnContinue = Button(this).apply {
            text          = "SELECT A TIER TO CONTINUE"
            textSize      = 12f
            typeface      = Typeface.DEFAULT_BOLD
            letterSpacing = 0.15f
            setTextColor(Color.WHITE)
            background    = GradientDrawable().apply {
                shape        = GradientDrawable.RECTANGLE
                cornerRadius = px(14).toFloat()
                setColor(Color.parseColor("#1a3a4a"))
            }
            layoutParams  = LinearLayout.LayoutParams(MATCH, px(54))
            isEnabled     = false
            alpha         = 0.45f
            setPadding(0, 0, 0, 0)
            setOnClickListener {
                when (selectedTier) {
                    1 -> startActivity(Intent(this@TierSelectionActivity, PassportActivity::class.java))
                    2 -> showToast("🪪 National ID — Coming Soon")
                    3 -> startActivity(Intent(this@TierSelectionActivity, DeviceTierActivity::class.java))
                }
            }
        }
        wrapper.addView(btnContinue)
        return wrapper
    }

    private fun cyberBorder(color: Int, radius: Float) = GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE; cornerRadius = px(radius.toInt()).toFloat()
        setStroke(1, color); setColor(Color.TRANSPARENT)
    }
    private fun adjustAlpha(color: Int, factor: Float): Int {
        val alpha = (Color.alpha(color) * factor).toInt().coerceIn(0, 255)
        return Color.argb(alpha, Color.red(color), Color.green(color), Color.blue(color))
    }
    private fun spacer(dp: Int) = View(this).apply { layoutParams = LinearLayout.LayoutParams(MATCH, px(dp)) }
    private fun px(dp: Int) = (dp * resources.displayMetrics.density).toInt()
    private fun showToast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
    private val MATCH = LinearLayout.LayoutParams.MATCH_PARENT
    private val WRAP  = LinearLayout.LayoutParams.WRAP_CONTENT
}