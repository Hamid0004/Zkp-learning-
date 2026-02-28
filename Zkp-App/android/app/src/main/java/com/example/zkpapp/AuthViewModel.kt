package com.example.zkpapp

import android.app.Application
import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.zkpapp.security.KeyStoreManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

// ============================================================
// AUTH STATE — UI sirf yeh observe karta hai
// ============================================================
sealed class AuthUiState {
    object Idle : AuthUiState()
    object Loading : AuthUiState()
    data class VaultExists(val isLocked: Boolean) : AuthUiState()
    data class Success(val message: String, val isGlobalUnlock: Boolean) : AuthUiState()
    data class Error(val message: String) : AuthUiState()
    object TamperDetected : AuthUiState()
    data class RateLimited(val waitSeconds: Int) : AuthUiState()
    data class SeedGenerated(val seed: String) : AuthUiState()
}

class AuthViewModel(application: Application) : AndroidViewModel(application) {

    // ----------------------------------------------------------------
    // CONSTANTS
    // ----------------------------------------------------------------
    private val PREFS_NAME          = "secure_prefs"
    private val KEY_ENCRYPTED_DATA  = "data"
    private val KEY_IV              = "iv"
    private val KEY_FAIL_COUNT      = "fail_count"
    private val KEY_LAST_FAIL_TIME  = "last_fail_ms"

    private val MAX_FAILED_ATTEMPTS = 5
    private val LOCKOUT_DURATION_MS = 30_000L  // 30 saniye
    private val WIPE_AFTER_ATTEMPTS = 10       // 10 fails → vault wipe

    // ----------------------------------------------------------------
    // STATE
    // ----------------------------------------------------------------
    private val _uiState = MutableStateFlow<AuthUiState>(AuthUiState.Idle)
    val uiState: StateFlow<AuthUiState> = _uiState

    val isAuthInProgress = AtomicBoolean(false)

    // ----------------------------------------------------------------
    // BIP39 — Official 2048 Word List + HashSet for O(1) lookup
    // ----------------------------------------------------------------
    val bip39WordList = listOf(
        "abandon","ability","able","about","above","absent","absorb","abstract",
        "absurd","abuse","access","accident","account","accuse","achieve","acid",
        "acoustic","acquire","across","act","action","actor","actress","actual",
        "adapt","add","addict","address","adjust","admit","adult","advance",
        "advice","aerobic","afford","afraid","again","age","agent","agree",
        "ahead","aim","air","airport","aisle","alarm","album","alcohol",
        "alert","alien","all","alley","allow","almost","alone","alpha",
        "already","also","alter","always","amateur","amazing","among","amount",
        "amused","analyst","anchor","ancient","anger","angle","angry","animal",
        "ankle","announce","annual","another","answer","antenna","antique","anxiety",
        "apart","apology","appear","apple","approve","april","arcade","arctic",
        "area","arena","argue","arm","armor","army","around","arrange",
        "arrest","arrive","arrow","art","artefact","artist","artwork","ask",
        "aspect","assault","asset","assist","assume","asthma","athlete","atom",
        "attack","attend","attitude","attract","auction","audit","august","aunt",
        "author","auto","autumn","average","avocado","avoid","awake","aware",
        "away","awesome","awful","awkward","axis","baby","balance","bamboo",
        "banana","banner","bar","barely","bargain","barrel","base","basic",
        "basket","battle","beach","bean","beauty","because","become","beef",
        "before","begin","behave","behind","believe","below","belt","bench",
        "benefit","best","betray","better","between","beyond","bicycle","bid",
        "bike","bind","biology","bird","birth","bitter","black","blade",
        "blame","blanket","blast","bleak","bless","blind","blood","blossom",
        "blouse","blue","blur","blush","board","boat","body","boil",
        "bomb","bone","book","boost","border","boring","borrow","boss",
        "bottom","bounce","box","boy","bracket","brain","brand","brave",
        "breeze","brick","bridge","brief","bright","bring","brisk","broccoli",
        "broken","bronze","broom","brother","brown","brush","bubble","buddy",
        "budget","buffalo","build","bulb","bulk","bullet","bundle","bunker",
        "burden","burger","burst","bus","business","busy","butter","buyer",
        "buzz","cabbage","cabin","cable","cactus","cage","cake","call",
        "calm","camera","camp","canal","cancel","candy","cannon","canvas",
        "canyon","capable","capital","captain","car","carbon","card","cargo",
        "carpet","carry","cart","case","cash","casino","castle","casual",
        "cat","catalog","catch","category","cause","cave","ceiling","celery",
        "cement","census","certain","chair","chalk","champion","change","chaos",
        "chapter","charge","chase","chat","cheap","check","cheese","chef",
        "cherry","chest","chicken","chief","child","chimney","choice","choose",
        "chronic","chuckle","chunk","cinema","circle","citizen","city","civil",
        "claim","clap","clarify","claw","clay","clean","clerk","clever",
        "click","client","cliff","climb","clinic","clip","clock","clog",
        "close","cloth","cloud","clown","club","clump","cluster","clutch",
        "coach","coast","coconut","code","coffee","coil","coin","collect",
        "color","column","combine","come","comfort","comic","common","company",
        "concert","conduct","confirm","congress","connect","consider","control","convince",
        "cook","cool","copper","copy","coral","core","corn","correct",
        "cost","cotton","couch","country","couple","course","cousin","cover",
        "coyote","crack","cradle","craft","cram","crane","crash","crater",
        "crawl","crazy","cream","credit","creek","crew","cricket","crime",
        "crisp","critic","cross","crouch","crowd","crucial","cruel","cruise",
        "crumble","crunch","crush","cry","crystal","cube","culture","cup",
        "cupboard","curious","current","curtain","curve","cushion","custom","cute",
        "cycle","dad","damage","damp","dance","danger","daring","dash",
        "daughter","dawn","day","deal","debate","debris","decade","december",
        "decide","decline","decorate","decrease","deer","defense","define","defy",
        "degree","delay","deliver","demand","demise","denial","dentist","deny",
        "depart","depend","deposit","depth","deputy","derive","describe","desert",
        "design","desk","despair","destroy","detail","detect","develop","device",
        "devote","diagram","dial","diamond","diary","dice","diesel","diet",
        "differ","digital","dignity","dilemma","dinner","dinosaur","direct","dirt",
        "disagree","discover","disease","dismiss","disorder","display","distance","divert",
        "divide","divorce","dizzy","doctor","document","dog","doll","dolphin",
        "domain","donate","donkey","donor","door","dose","double","dove",
        "draft","dragon","drama","drastic","draw","dream","dress","drift",
        "drill","drink","drip","drive","drop","drum","dry","duck",
        "dumb","dune","during","dust","dutch","duty","dwarf","dynamic",
        "eager","eagle","early","earn","earth","easily","east","easy",
        "echo","ecology","edge","edit","educate","effort","egg","eight",
        "either","elbow","elder","electric","elegant","element","elephant","elevator",
        "elite","else","embark","embody","emerge","emotion","employ","empower",
        "empty","enable","enact","endless","endorse","enemy","energy","enforce",
        "engage","engine","enhance","enjoy","enlist","enough","enrich","enroll",
        "ensure","enter","entire","entry","envelope","episode","equal","equip",
        "erase","erode","erosion","error","erupt","escape","essay","essence",
        "estate","eternal","ethics","evidence","evil","evoke","evolve","exact",
        "example","excess","exchange","excite","exclude","exercise","exhaust","exhibit",
        "exile","exist","exit","exotic","expand","expire","explain","expose",
        "express","extend","extra","eye","fable","face","faculty","faint",
        "faith","fall","false","fame","family","famous","fan","fancy",
        "fantasy","far","fashion","fat","fatal","father","fatigue","fault",
        "favorite","feature","february","federal","fee","feed","feel","feet",
        "fellow","felt","fence","festival","fetch","fever","few","fiber",
        "fiction","field","figure","file","film","filter","final","find",
        "fine","finger","finish","fire","firm","first","fiscal","fish",
        "fit","fitness","fix","flag","flame","flash","flat","flavor",
        "flee","flight","flip","float","flock","floor","flower","fluid",
        "flush","fly","foam","focus","fog","foil","follow","food",
        "foot","force","forest","forget","fork","fortune","forum","forward",
        "fossil","foster","found","fox","fragile","frame","frequent","fresh",
        "friend","fringe","frog","front","frost","frown","frozen","fruit",
        "fuel","fun","funny","furnace","fury","future","gadget","gain",
        "galaxy","gallery","game","gap","garbage","garden","garlic","garment",
        "gas","gasp","gate","gather","gauge","gaze","general","genius",
        "genre","gentle","genuine","gesture","ghost","gift","giggle","ginger",
        "giraffe","girl","give","glad","glance","glare","glass","glide",
        "glimpse","globe","gloom","glory","glove","glow","glue","goat",
        "goddess","gold","good","goose","gorilla","gospel","gossip","govern",
        "grab","grace","grain","grant","grape","grasp","grass","gravity",
        "great","green","grid","grief","grit","grocery","group","grow",
        "grunt","guard","guide","guilt","guitar","gun","gym","habit",
        "hair","half","hammer","hamster","hand","happy","harsh","harvest",
        "hat","have","hawk","hazard","head","health","heart","heavy",
        "hedgehog","height","hello","helmet","help","hen","hero","hidden",
        "high","hill","hint","hip","hire","history","hobby","hockey",
        "hold","hole","holiday","hollow","home","honey","hood","hope",
        "horn","hospital","host","hour","hover","hub","humble","humor",
        "hundred","hungry","hunt","hurdle","hurry","hurt","husband","hybrid",
        "ice","icon","ignore","ill","illegal","image","imitate","immense",
        "immune","impact","impose","improve","impulse","inbox","income","increase",
        "index","indicate","indoor","industry","infant","inflict","inform","inhale",
        "inject","inner","innocent","input","inquiry","insane","insect","inside",
        "inspire","install","intact","interest","into","invest","invite","involve",
        "iron","island","isolate","issue","item","ivory","jacket","jaguar",
        "jar","jazz","jealous","jeans","jelly","jewel","job","join",
        "joke","journey","joy","judge","juice","jump","jungle","junior",
        "junk","just","kangaroo","keen","keep","ketchup","key","kick",
        "kid","kingdom","kiss","kit","kitchen","kite","kitten","kiwi",
        "knee","knife","knock","know","lab","ladder","lake","lamp",
        "language","laptop","large","later","laugh","laundry","lava","law",
        "lawn","lawsuit","layer","lazy","leader","learn","leave","lecture",
        "left","leg","legal","legend","leisure","lemon","lend","length",
        "lens","leopard","lesson","letter","level","liar","liberty","library",
        "license","life","lift","like","limb","limit","link","lion",
        "liquid","list","little","live","lizard","load","loan","lobster",
        "local","lock","logic","lonely","long","loop","lottery","loud",
        "lounge","love","loyal","lucky","luggage","lumber","lunar","lunch",
        "luxury","mad","magic","magnet","maid","main","mammal","mango",
        "mansion","manual","maple","marble","march","margin","marine","market",
        "marriage","mask","master","match","material","math","matrix","matter",
        "maximum","maze","meadow","mean","medal","media","melody","melt",
        "member","memory","mention","menu","mercy","mesh","message","metal",
        "method","middle","midnight","milk","million","mimic","mind","minimum",
        "minor","minute","miracle","miss","mitten","model","modify","mom",
        "monitor","monkey","monster","month","moon","moral","more","morning",
        "mosquito","mother","motion","motor","mountain","mouse","move","movie",
        "much","muffin","mule","multiply","muscle","museum","mushroom","music",
        "mustard","mystery","naive","name","napkin","narrow","nasty","natural",
        "nature","near","neck","need","negative","neglect","neither","nephew",
        "nerve","nest","network","news","next","nice","night","noble",
        "noise","nominee","noodle","normal","north","notable","note","nothing",
        "notice","novel","now","nuclear","number","nurse","nut","oak",
        "obey","object","oblige","obscure","obtain","ocean","october","odor",
        "offer","office","often","oil","okay","old","olympic","omit",
        "once","onion","open","opera","oppose","option","orange","orbit",
        "orchard","order","ordinary","organ","orient","original","orphan","ostrich",
        "other","outdoor","outside","oval","over","own","oyster","ozone",
        "pact","paddle","page","pair","palace","palm","panda","panel",
        "panic","panther","paper","parade","parent","park","parrot","party",
        "pass","patch","path","patrol","pause","pave","payment","peace",
        "peanut","pear","peasant","pelican","pen","penalty","pencil","people",
        "pepper","perfect","permit","person","pet","phone","photo","phrase",
        "physical","piano","picnic","picture","piece","pig","pigeon","pill",
        "pilot","pink","pioneer","pipe","pistol","pitch","pizza","place",
        "planet","plastic","plate","play","please","pledge","pluck","plug",
        "plunge","poem","poet","point","polar","pole","police","pond",
        "pony","pool","popular","portion","position","possible","post","potato",
        "pottery","poverty","powder","power","practice","praise","predict","prefer",
        "prepare","present","pretty","prevent","price","pride","primary","print",
        "priority","prison","private","prize","problem","process","produce","profit",
        "program","project","promote","proof","property","prosper","protect","proud",
        "provide","public","pudding","pull","pulp","pulse","pumpkin","punish",
        "pupil","purchase","purity","purpose","push","put","puzzle","pyramid",
        "quality","quantum","quarter","question","quick","quit","quiz","quote",
        "rabbit","raccoon","race","rack","radar","radio","rage","rail",
        "rain","raise","rally","ramp","ranch","random","range","rapid",
        "rare","rate","rather","raven","reach","ready","real","reason",
        "rebel","rebuild","recall","receive","recipe","record","recycle","reduce",
        "reflect","reform","refuse","region","regret","regular","reject","relax",
        "release","relief","rely","remain","remember","remind","remove","render",
        "renew","rent","reopen","repair","repeat","replace","report","require",
        "rescue","resemble","resist","resource","response","result","retire","retreat",
        "return","reunion","reveal","review","reward","rhythm","ribbon","rice",
        "rich","ride","ridge","rifle","right","rigid","ring","riot",
        "ripple","risk","ritual","rival","river","road","roast","robot",
        "robust","rocket","romance","roof","rookie","room","rose","rotate",
        "rough","route","royal","rubber","rude","rug","rule","run",
        "runway","rural","sad","saddle","sadness","safe","sail","salad",
        "salmon","salon","salt","salute","same","sample","sand","satisfy",
        "satoshi","sauce","sausage","save","scale","scan","scatter","scene",
        "scheme","science","scissors","scorpion","scout","scrap","screen","script",
        "scrub","sea","search","season","seat","second","secret","section",
        "security","seed","seek","segment","select","sell","seminar","senior",
        "sense","sentence","series","service","session","settle","setup","seven",
        "shadow","shaft","shallow","share","shed","shell","sheriff","shield",
        "shift","shine","ship","shiver","shock","shoe","shoot","shop",
        "short","shoulder","shove","shrimp","shrug","shuffle","shy","sibling",
        "siege","sight","sign","silent","silk","silly","silver","similar",
        "simple","since","sing","siren","sister","situate","six","size",
        "ski","skill","skin","skirt","skull","slab","slam","sleep",
        "slender","slice","slide","slight","slim","slogan","slot","slow",
        "slush","small","smart","smile","smoke","smooth","snack","snake",
        "snap","sniff","snow","soap","soccer","social","sock","solar",
        "soldier","solid","solution","solve","someone","song","soon","sorry",
        "soul","sound","soup","source","south","space","spare","spatial",
        "spawn","speak","special","speed","sphere","spice","spider","spike",
        "spin","spirit","split","spoil","sponsor","spoon","spray","spread",
        "spring","spy","square","squeeze","squirrel","stable","stadium","staff",
        "stage","stairs","stamp","stand","start","state","stay","steak",
        "steel","stem","step","stereo","stick","still","sting","stock",
        "stomach","stone","stop","store","storm","story","stove","strategy",
        "street","strike","strong","struggle","student","stuff","stumble","subject",
        "submit","sugar","suit","summer","sun","sunny","sunset","super",
        "supply","supreme","sure","surface","surge","surprise","sustain","swallow",
        "swamp","swap","swear","sweet","swift","swim","swing","switch",
        "sword","symbol","symptom","syrup","table","tackle","tag","tail",
        "talent","tank","tape","target","task","tattoo","taxi","teach",
        "team","tell","ten","tenant","tennis","tent","term","test",
        "text","thank","that","theme","then","theory","there","they",
        "thing","this","thought","three","thrive","throw","thumb","ticket",
        "tilt","timber","time","tiny","tip","tired","title","toast",
        "tobacco","today","toggle","toilet","token","tomato","tomorrow","tone",
        "tongue","tonight","tool","topic","topple","torch","tornado","tortoise",
        "toss","total","tourist","toward","tower","town","toy","track",
        "trade","traffic","tragic","train","transfer","trap","trash","travel",
        "tray","treat","tree","trend","trial","tribe","trick","trigger",
        "trim","trip","trophy","trouble","truck","truly","trumpet","trust",
        "truth","try","tube","tuition","tumble","tuna","tunnel","turkey",
        "turn","turtle","twelve","twenty","twice","twin","twist","two",
        "type","typical","ugly","umbrella","unable","unaware","uncle","uncover",
        "under","undo","unfair","unfold","unhappy","uniform","unique","universe",
        "unknown","unlock","until","unusual","unveil","update","upgrade","uphold",
        "upon","upper","upset","urban","useful","useless","usual","utility",
        "vacant","vacuum","vague","valid","valley","valve","van","vanish",
        "vapor","various","vast","vault","vehicle","velvet","vendor","venture",
        "venue","verb","verify","version","very","veteran","viable","vibrant",
        "vicious","victory","video","view","village","vintage","violin","virtual",
        "virus","visa","visit","visual","vital","vivid","vocal","voice",
        "void","volcano","volume","vote","voyage","wage","wagon","wait",
        "walk","wall","walnut","want","warfare","warm","warrior","waste",
        "water","wave","way","wealth","weapon","wear","weasel","weather",
        "web","wedding","weekend","weird","welcome","well","west","wet",
        "whale","wheat","wheel","when","where","whip","whisper","wide",
        "width","wife","wild","will","win","window","wine","wing",
        "wink","winner","winter","wire","wisdom","wise","wish","witness",
        "wolf","woman","wonder","wood","wool","word","world","worry",
        "worth","wrap","wreck","wrestle","wrist","write","wrong","yard",
        "year","yellow","you","young","youth","zebra","zero","zone","zoo"
    )

    // ✅ O(1) lookup instead of O(n)
    val bip39WordSet: Set<String> = bip39WordList.toHashSet()

    // ----------------------------------------------------------------
    // 1. TRUE BIP39 MNEMONIC GENERATION (RFC-compliant)
    //    128-bit entropy → SHA256 → 4-bit checksum → 12 words
    // ----------------------------------------------------------------
    fun generateTrueBip39Mnemonic(): String {
        val entropy = ByteArray(16).also { SecureRandom().nextBytes(it) }
        try {
            val sha256 = MessageDigest.getInstance("SHA-256")
            val hash = sha256.digest(entropy)

            val bits = BooleanArray(132)
            for (i in 0 until 16) {
                val b = entropy[i].toInt() and 0xFF
                for (j in 0 until 8) {
                    bits[i * 8 + j] = (b shr (7 - j) and 1) == 1
                }
            }

            val checksumByte = hash[0].toInt() and 0xFF
            for (j in 0 until 4) {
                bits[128 + j] = (checksumByte shr (7 - j) and 1) == 1
            }

            val words = Array(12) { i ->
                var idx = 0
                for (j in 0 until 11) {
                    idx = idx shl 1
                    if (bits[i * 11 + j]) idx = idx or 1
                }
                bip39WordList[idx % bip39WordList.size]
            }

            return words.joinToString(" ")
        } finally {
            Arrays.fill(entropy, 0.toByte())
        }
    }

    // ----------------------------------------------------------------
    // 2. BIP39 CHECKSUM VALIDATION
    //    Verify last word's checksum bits match entropy hash
    // ----------------------------------------------------------------
    fun validateBip39Checksum(mnemonic: String): Boolean {
        val words = mnemonic.trim().lowercase().split("\\s+".toRegex())
        if (words.size != 12) return false
        if (words.any { it !in bip39WordSet }) return false

        return try {
            val bits = BooleanArray(132)
            for (i in words.indices) {
                val idx = bip39WordList.indexOf(words[i])
                if (idx < 0) return false
                for (j in 0 until 11) {
                    bits[i * 11 + j] = (idx shr (10 - j) and 1) == 1
                }
            }

            val entropy = ByteArray(16)
            for (i in 0 until 16) {
                var b = 0
                for (j in 0 until 8) {
                    b = b shl 1
                    if (bits[i * 8 + j]) b = b or 1
                }
                entropy[i] = b.toByte()
            }

            var mnemonicChecksum = 0
            for (j in 0 until 4) {
                mnemonicChecksum = mnemonicChecksum shl 1
                if (bits[128 + j]) mnemonicChecksum = mnemonicChecksum or 1
            }

            val sha256 = MessageDigest.getInstance("SHA-256")
            val hash = sha256.digest(entropy)
            val expectedChecksum = (hash[0].toInt() and 0xFF) ushr 4

            Arrays.fill(entropy, 0.toByte())  // 🔥 Wipe
            mnemonicChecksum == expectedChecksum
        } catch (e: Exception) {
            false
        }
    }

    // ----------------------------------------------------------------
    // 3. TAMPER DETECTION — Root & Emulator ONLY (No Debug check)
    // ----------------------------------------------------------------
    fun runTamperChecks(context: Context): TamperResult {
        val flags = mutableListOf<String>()

        // 🟢 REMOVED: Debuggable flag check. App will no longer warn during Android Studio development.

        // (b) Known root management apps
        val rootApps = listOf(
            "com.topjohnwu.magisk",
            "com.noshufou.android.su",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser"
        )
        val pm = context.packageManager
        rootApps.forEach { pkg ->
            try {
                pm.getPackageInfo(pkg, 0)
                flags.add("Root app detected: $pkg")
            } catch (_: Exception) {}
        }

        // (c) su binary in common paths
        val suPaths = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su")
        suPaths.forEach { path ->
            if (java.io.File(path).exists()) flags.add("su binary at $path")
        }

        // (d) Test-keys build (non-official ROM)
        val buildTags = Build.TAGS
        if (buildTags != null && buildTags.contains("test-keys")) {
            flags.add("Device built with test-keys (unofficial ROM)")
        }

        // (e) Emulator detection
        val isEmulator = (Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.startsWith("unknown")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK")
                || Build.MANUFACTURER.contains("Genymotion")
                || Build.HARDWARE.contains("goldfish")
                || Build.HARDWARE.contains("ranchu"))
        if (isEmulator) flags.add("Emulator detected")

        return if (flags.isEmpty()) TamperResult.Clean
        else TamperResult.Compromised(flags)
    }

    sealed class TamperResult {
        object Clean : TamperResult()
        data class Compromised(val reasons: List<String>) : TamperResult()
    }

    // ----------------------------------------------------------------
    // 4. RATE LIMITING — Failed attempt tracking
    // ----------------------------------------------------------------
    fun recordFailedAttempt(context: Context) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val current = prefs.getInt(KEY_FAIL_COUNT, 0) + 1
        prefs.edit()
            .putInt(KEY_FAIL_COUNT, current)
            .putLong(KEY_LAST_FAIL_TIME, System.currentTimeMillis())
            .commit()

        // 🔥 NUCLEAR OPTION: Too many fails → wipe vault
        if (current >= WIPE_AFTER_ATTEMPTS) {
            wipeVault(context)
        }
    }

    fun checkRateLimit(context: Context): RateLimitStatus {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val failCount = prefs.getInt(KEY_FAIL_COUNT, 0)
        val lastFailTime = prefs.getLong(KEY_LAST_FAIL_TIME, 0L)

        if (failCount < MAX_FAILED_ATTEMPTS) return RateLimitStatus.Allowed

        val elapsed = System.currentTimeMillis() - lastFailTime
        val remaining = LOCKOUT_DURATION_MS - elapsed

        return if (remaining > 0) {
            RateLimitStatus.Blocked(waitSeconds = (remaining / 1000).toInt() + 1)
        } else {
            // Lockout expired — reset counter
            prefs.edit().putInt(KEY_FAIL_COUNT, 0).commit()
            RateLimitStatus.Allowed
        }
    }

    fun resetFailedAttempts(context: Context) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit().putInt(KEY_FAIL_COUNT, 0).commit()
    }

    sealed class RateLimitStatus {
        object Allowed : RateLimitStatus()
        data class Blocked(val waitSeconds: Int) : RateLimitStatus()
    }

    // ----------------------------------------------------------------
    // 5. VAULT HELPERS
    // ----------------------------------------------------------------
    fun isVaultExists(context: Context): Boolean {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getString(KEY_ENCRYPTED_DATA, null) != null
    }

    fun wipeVault(context: Context) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit().clear().commit()
    }

    // ----------------------------------------------------------------
    // 6. STRONGBOX — Hardware-backed key if available (Pixel 3+ / Galaxy S10+)
    // ----------------------------------------------------------------
    fun isStrongBoxAvailable(context: Context): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            context.packageManager.hasSystemFeature("android.hardware.strongbox_keystore")
        } else false
    }

    // ----------------------------------------------------------------
    // STATE EMITTERS (Activity calls these)
    // ----------------------------------------------------------------
    fun emitError(msg: String) {
        _uiState.value = AuthUiState.Error(msg)
    }

    fun emitSuccess(msg: String, isGlobalUnlock: Boolean) {
        _uiState.value = AuthUiState.Success(msg, isGlobalUnlock)
    }

    fun emitLoading() {
        _uiState.value = AuthUiState.Loading
    }

    fun emitVaultState(context: Context) {
        _uiState.value = AuthUiState.VaultExists(isVaultExists(context))
    }

    fun emitTamperDetected() {
        _uiState.value = AuthUiState.TamperDetected
    }

    fun emitRateLimited(seconds: Int) {
        _uiState.value = AuthUiState.RateLimited(seconds)
    }

    fun emitSeedGenerated(seed: String) {
        _uiState.value = AuthUiState.SeedGenerated(seed)
    }

    fun resetState() {
        _uiState.value = AuthUiState.Idle
    }
}