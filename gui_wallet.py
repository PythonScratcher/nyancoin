#!/usr/bin/env python3
"""NyanCoin GUI wallet: the same wallet as wallet.py, with windows and buttons.

  python3 gui_wallet.py

Create a wallet (with a recovery phrase), restore one from its phrase, or open a wallet file;
then see your balance and history, and send coins. Your keys never leave this computer:
the node only ever receives signed payments. The password is asked for each payment and the
key is not kept in memory between payments.

Needs: Python 3 with Tkinter (Windows/macOS: included; Debian/Ubuntu: sudo apt install python3-tk)
and  pip install cryptography.  Self-contained: wallet.py is not needed next to it.
Wallet files are the same format as wallet.py's, so you can use either program.
"""
import argparse, getpass, hashlib, hmac, http.client, ipaddress, json, os, random, socket, ssl
import sys, threading, unicodedata
import urllib.error, urllib.request
from decimal import Decimal, InvalidOperation
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# >>> SHARED RULES BEGIN (locked: editing anything between BEGIN and END stops the program from starting)
# ======================================================================
# SHARED RULES - identical in node.py / miner.py / wallet.py (keep in sync;
# programs refuse to talk to a node whose RULES fingerprint differs)
# ======================================================================
# ---------------------------------------------------------------- consensus
CHAIN_ID = "nyancoin-2"          # v2: slower supply schedule (new chain)
COIN = 10 ** 8                  # smallest unit = 1e-8 NYAN
REWARD0 = 1 * COIN             # 1 NYAN per block...
HALVING = 10_500_000           # ...halving every 10.5M blocks (~3.3 years at 10 s) -> 21M max
INIT_BITS, MIN_BITS, MAX_BITS = 20, 20, 60    # difficulty can never collapse below INIT
RETARGET, TARGET_SPACING = 10, 10      # blocks, seconds
MAX_TXS, MAX_FUTURE, MAX_INT = 500, 7200, 2 ** 53
MAX_BLOCK_BYTES = 1_000_000

# ------------------------------------------------------------ runtime globals
NET_GUARD = False       # set by the node: refuse unpinned peers on private/loopback IPs
HOME = os.environ.get("NYAN_HOME") or os.path.expanduser("~/.nyancoin")


def H(x):
    return hashlib.sha256(x if isinstance(x, bytes) else x.encode()).hexdigest()


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"))


RULES = H(canon([CHAIN_ID, COIN, REWARD0, HALVING, INIT_BITS, MIN_BITS, MAX_BITS, RETARGET,
                 TARGET_SPACING, MAX_TXS, MAX_FUTURE, MAX_INT, MAX_BLOCK_BYTES]))
# ^ fingerprint of the shared consensus constants; wallet/miner refuse nodes that differ


def make_addr(pub_hex):
    body = H(bytes.fromhex(pub_hex))[:40]
    return "NYAN" + body + H(body)[:4]


def valid_addr(a):
    return (isinstance(a, str) and len(a) == 48 and a.startswith("NYAN")
            and all(c in "0123456789abcdef" for c in a[4:])
            and H(a[4:44])[:4] == a[44:])


def tx_body(t):
    return canon({k: t[k] for k in ("chain", "from", "to", "amount", "fee", "nonce")})



# --- TLS with key pinning (no certificate authority needed) ---------------
# A node's identity is the SHA-256 of its TLS public key (the "pin"). Clients either
# get it up front (https://host:port#PIN, strongest) or trust-on-first-use like SSH.
PIN_LOCK = threading.Lock()


def spki_pin(der_cert):
    pub = x509.load_der_x509_certificate(der_cert).public_key()
    return H(pub.public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo))


def norm_ip(ip):
    """ipaddress object; IPv4-mapped IPv6 (::ffff:1.2.3.4) is treated as plain IPv4."""
    a = ipaddress.ip_address(str(ip).split("%")[0])
    return a.ipv4_mapped if a.version == 6 and a.ipv4_mapped else a


def hostkey(host, port):
    host = str(host).strip("[]").lower()
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def check_pin(host, port, spki, pin):
    if pin:
        if spki != pin:
            raise ssl.SSLError(f"TLS pin mismatch for {host}:{port}")
        return
    path, key = os.path.join(HOME, "known_hosts.json"), hostkey(host, port)
    with PIN_LOCK:
        try:
            with open(path) as f:
                store = json.load(f)
        except Exception:
            store = {}
        if key not in store:
            store[key] = spki
            os.makedirs(HOME, exist_ok=True)
            with open(path + ".tmp", "w") as f:
                json.dump(store, f)
            os.replace(path + ".tmp", path)
        elif store[key] != spki:
            raise ssl.SSLError(f"TLS key for {key} CHANGED (possible MITM attack). "
                               f"If you trust the change, remove it from {path}")


def known_pin(url):
    """Pin we've already recorded (TOFU) for this host:port, or ''."""
    try:
        u = urlsplit(url)
        with PIN_LOCK, open(os.path.join(HOME, "known_hosts.json")) as f:
            return json.load(f).get(hostkey(u.hostname, u.port or 443), "")
    except Exception:
        return ""


def resolve(url):
    try:
        return socket.getaddrinfo(urlsplit(url).hostname, None)[0][4][0]
    except Exception:
        return None


def net_group(ip):
    if not ip:
        return None
    a = norm_ip(ip)                            # same /16 (IPv4) or /32 (IPv6) = same group
    return str(ipaddress.ip_network(f"{a}/{16 if a.version == 4 else 32}", strict=False))


class PinnedConn(http.client.HTTPSConnection):
    pin = None

    def connect(self):
        super().connect()                      # encrypted channel up; verify identity
        if NET_GUARD and not self.pin:         # check the REAL connected IP (DNS-rebinding proof)
            try:
                ok = norm_ip(self.sock.getpeername()[0]).is_global
            except ValueError:
                ok = False
            if not ok:
                self.sock.close()
                raise ssl.SSLError("refusing unpinned peer on a non-public address")
        check_pin(self.host, self.port, spki_pin(self.sock.getpeercert(binary_form=True)), self.pin)


class PinnedHandler(urllib.request.HTTPSHandler):
    def __init__(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE   # identity = pin, below
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        super().__init__(context=ctx)

    def https_open(self, req):
        def mk(host, **kw):
            c = PinnedConn(host, **kw)
            c.pin = req.fragment or None
            return c
        return self.do_open(mk, req, context=self._context)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


OPENER = urllib.request.build_opener(PinnedHandler(), NoRedirect())


def http(url, path, obj=None, timeout=8, limit=20_000_000):
    base, _, pin = url.partition("#")
    req = urllib.request.Request(base.rstrip("/") + path + ("#" + pin if pin else ""),
                                 data=None if obj is None else json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"})
    with OPENER.open(req, timeout=timeout) as r:
        data = r.read(limit + 1)
        if len(data) > limit:
            raise ValueError("response too large")
        return json.loads(data)



def check_rules(node_url):
    """Refuse to talk to a node running different consensus rules (version mismatch)."""
    if http(node_url, "/info").get("rules") != RULES:
        sys.exit("version mismatch: this program and the node use different NyanCoin rules - update both")
# <<< SHARED RULES END

# ---- rules lock: refuse to run if the shared rules above were modified ----------------
EXPECTED_SHARED_HASH = "b7ad8db8374022c2ff90ad084f567ec75ecd716f861485f32f782d71e97efe74"


def _verify_rules_lock():
    try:
        with open(__file__, encoding="utf-8") as f:
            src = f.read().replace("\r\n", "\n")
    except (OSError, NameError):
        return
    region = src[src.index("# >>> SHARED RULES" + " BEGIN"):src.index("# <<< SHARED RULES" + " END")]
    if H(region) != EXPECTED_SHARED_HASH:
        sys.exit("The shared consensus rules in this file were modified. Running modified rules "
                 "would split you from the NyanCoin network, so this program refuses to start. "
                 "Re-download the original file.")


_verify_rules_lock()

# ======================================================================
# wallet code
# ======================================================================
VERSION = "1.0.0"

# Default node: the official seed. Run your own node and use --node https://127.0.0.1:8001 for best privacy.
DEFAULT_NODE = "https://inter.net.sh:8001#aacf9733d8a238bc0f8a62232e5ab5b804cd3fe80b32e90c58bd70ff52f1fc41"


def get_password(confirm=False):
    pw = os.environ.get("NYAN_PASS") or getpass.getpass("Wallet password: ")
    if len(pw) < 12:
        sys.exit("password must be at least 12 characters (use a passphrase)")
    if confirm and not os.environ.get("NYAN_PASS") and getpass.getpass("Repeat: ") != pw:
        sys.exit("passwords differ")
    return pw.encode()


# ---- recovery phrase (BIP39 English word list + checksum) --------------------------
# The phrase encodes 128/256 random bits plus a checksum. The NyanCoin key is derived from it
# with BIP39 (PBKDF2-HMAC-SHA512) then SLIP-10 Ed25519 master key. Anyone with the phrase
# can spend your coins: write it on paper, never type it into a website.
BIP39_WORDS = """
abandon ability able about above absent absorb abstract absurd abuse access accident account accuse
achieve acid acoustic acquire across act action actor actress actual adapt add addict address adjust
admit adult advance advice aerobic affair afford afraid again age agent agree ahead aim air airport
aisle alarm album alcohol alert alien all alley allow almost alone alpha already also alter always
amateur amazing among amount amused analyst anchor ancient anger angle angry animal ankle announce
annual another answer antenna antique anxiety any apart apology appear apple approve april arch
arctic area arena argue arm armed armor army around arrange arrest arrive arrow art artefact artist
artwork ask aspect assault asset assist assume asthma athlete atom attack attend attitude attract
auction audit august aunt author auto autumn average avocado avoid awake aware away awesome awful
awkward axis baby bachelor bacon badge bag balance balcony ball bamboo banana banner bar barely
bargain barrel base basic basket battle beach bean beauty because become beef before begin behave
behind believe below belt bench benefit best betray better between beyond bicycle bid bike bind
biology bird birth bitter black blade blame blanket blast bleak bless blind blood blossom blouse
blue blur blush board boat body boil bomb bone bonus book boost border boring borrow boss bottom
bounce box boy bracket brain brand brass brave bread breeze brick bridge brief bright bring brisk
broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build bulb bulk bullet
bundle bunker burden burger burst bus business busy butter buyer buzz cabbage cabin cable cactus
cage cake call calm camera camp can canal cancel candy cannon canoe canvas canyon capable capital
captain car carbon card cargo carpet carry cart case cash casino castle casual cat catalog catch
category cattle caught cause caution cave ceiling celery cement census century cereal certain chair
chalk champion change chaos chapter charge chase chat cheap check cheese chef cherry chest chicken
chief child chimney choice choose chronic chuckle chunk churn cigar cinnamon circle citizen city
civil claim clap clarify claw clay clean clerk clever click client cliff climb clinic clip clock
clog close cloth cloud clown club clump cluster clutch coach coast coconut code coffee coil coin
collect color column combine come comfort comic common company concert conduct confirm congress
connect consider control convince cook cool copper copy coral core corn correct cost cotton couch
country couple course cousin cover coyote crack cradle craft cram crane crash crater crawl crazy
cream credit creek crew cricket crime crisp critic crop cross crouch crowd crucial cruel cruise
crumble crunch crush cry crystal cube culture cup cupboard curious current curtain curve cushion
custom cute cycle dad damage damp dance danger daring dash daughter dawn day deal debate debris
decade december decide decline decorate decrease deer defense define defy degree delay deliver
demand demise denial dentist deny depart depend deposit depth deputy derive describe desert design
desk despair destroy detail detect develop device devote diagram dial diamond diary dice diesel diet
differ digital dignity dilemma dinner dinosaur direct dirt disagree discover disease dish dismiss
disorder display distance divert divide divorce dizzy doctor document dog doll dolphin domain donate
donkey donor door dose double dove draft dragon drama drastic draw dream dress drift drill drink
drip drive drop drum dry duck dumb dune during dust dutch duty dwarf dynamic eager eagle early earn
earth easily east easy echo ecology economy edge edit educate effort egg eight either elbow elder
electric elegant element elephant elevator elite else embark embody embrace emerge emotion employ
empower empty enable enact end endless endorse enemy energy enforce engage engine enhance enjoy
enlist enough enrich enroll ensure enter entire entry envelope episode equal equip era erase erode
erosion error erupt escape essay essence estate eternal ethics evidence evil evoke evolve exact
example excess exchange excite exclude excuse execute exercise exhaust exhibit exile exist exit
exotic expand expect expire explain expose express extend extra eye eyebrow fabric face faculty fade
faint faith fall false fame family famous fan fancy fantasy farm fashion fat fatal father fatigue
fault favorite feature february federal fee feed feel female fence festival fetch fever few fiber
fiction field figure file film filter final find fine finger finish fire firm first fiscal fish fit
fitness fix flag flame flash flat flavor flee flight flip float flock floor flower fluid flush fly
foam focus fog foil fold follow food foot force forest forget fork fortune forum forward fossil
foster found fox fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel
fun funny furnace fury future gadget gain galaxy gallery game gap garage garbage garden garlic
garment gas gasp gate gather gauge gaze general genius genre gentle genuine gesture ghost giant gift
giggle ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow
glue goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape
grass gravity great green grid grief grit grocery group grow grunt guard guess guide guilt guitar
gun gym habit hair half hammer hamster hand happy harbor hard harsh harvest hat have hawk hazard
head health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint hip hire
history hobby hockey hold hole holiday hollow home honey hood hope horn horror horse hospital host
hotel hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt husband hybrid
ice icon idea identify idle ignore ill illegal illness image imitate immense immune impact impose
improve impulse inch include income increase index indicate indoor industry infant inflict inform
inhale inherit initial inject injury inmate inner innocent input inquiry insane insect inside
inspire install intact interest into invest invite involve iron island isolate issue item ivory
jacket jaguar jar jazz jealous jeans jelly jewel job join joke journey joy judge juice jump jungle
junior junk just kangaroo keen keep ketchup key kick kid kidney kind kingdom kiss kit kitchen kite
kitten kiwi knee knife knock know lab label labor ladder lady lake lamp language laptop large later
latin laugh laundry lava law lawn lawsuit layer lazy leader leaf learn leave lecture left leg legal
legend leisure lemon lend length lens leopard lesson letter level liar liberty library license life
lift light like limb limit link lion liquid list little live lizard load loan lobster local lock
logic lonely long loop lottery loud lounge love loyal lucky luggage lumber lunar lunch luxury lyrics
machine mad magic magnet maid mail main major make mammal man manage mandate mango mansion manual
maple marble march margin marine market marriage mask mass master match material math matrix matter
maximum maze meadow mean measure meat mechanic medal media melody melt member memory mention menu
mercy merge merit merry mesh message metal method middle midnight milk million mimic mind minimum
minor minute miracle mirror misery miss mistake mix mixed mixture mobile model modify mom moment
monitor monkey monster month moon moral more morning mosquito mother motion motor mountain mouse
move movie much muffin mule multiply muscle museum mushroom music must mutual myself mystery myth
naive name napkin narrow nasty nation nature near neck need negative neglect neither nephew nerve
nest net network neutral never news next nice night noble noise nominee noodle normal north nose
notable note nothing notice novel now nuclear number nurse nut oak obey object oblige obscure
observe obtain obvious occur ocean october odor off offer office often oil okay old olive olympic
omit once one onion online only open opera opinion oppose option orange orbit orchard order ordinary
organ orient original orphan ostrich other outdoor outer output outside oval oven over own owner
oxygen oyster ozone pact paddle page pair palace palm panda panel panic panther paper parade parent
park parrot party pass patch path patient patrol pattern pause pave payment peace peanut pear
peasant pelican pen penalty pencil people pepper perfect permit person pet phone photo phrase
physical piano picnic picture piece pig pigeon pill pilot pink pioneer pipe pistol pitch pizza place
planet plastic plate play please pledge pluck plug plunge poem poet point polar pole police pond
pony pool popular portion position possible post potato pottery poverty powder power practice praise
predict prefer prepare present pretty prevent price pride primary print priority prison private
prize problem process produce profit program project promote proof property prosper protect proud
provide public pudding pull pulp pulse pumpkin punch pupil puppy purchase purity purpose purse push
put puzzle pyramid quality quantum quarter question quick quit quiz quote rabbit raccoon race rack
radar radio rail rain raise rally ramp ranch random range rapid rare rate rather raven raw razor
ready real reason rebel rebuild recall receive recipe record recycle reduce reflect reform refuse
region regret regular reject relax release relief rely remain remember remind remove render renew
rent reopen repair repeat replace report require rescue resemble resist resource response result
retire retreat return reunion reveal review reward rhythm rib ribbon rice rich ride ridge rifle
right rigid ring riot ripple risk ritual rival river road roast robot robust rocket romance roof
rookie room rose rotate rough round route royal rubber rude rug rule run runway rural sad saddle
sadness safe sail salad salmon salon salt salute same sample sand satisfy satoshi sauce sausage save
say scale scan scare scatter scene scheme school science scissors scorpion scout scrap screen script
scrub sea search season seat second secret section security seed seek segment select sell seminar
senior sense sentence series service session settle setup seven shadow shaft shallow share shed
shell sheriff shield shift shine ship shiver shock shoe shoot shop short shoulder shove shrimp shrug
shuffle shy sibling sick side siege sight sign silent silk silly silver similar simple since sing
siren sister situate six size skate sketch ski skill skin skirt skull slab slam sleep slender slice
slide slight slim slogan slot slow slush small smart smile smoke smooth snack snake snap sniff snow
soap soccer social sock soda soft solar soldier solid solution solve someone song soon sorry sort
soul sound soup source south space spare spatial spawn speak special speed spell spend sphere spice
spider spike spin spirit split spoil sponsor spoon sport spot spray spread spring spy square squeeze
squirrel stable stadium staff stage stairs stamp stand start state stay steak steel stem step stereo
stick still sting stock stomach stone stool story stove strategy street strike strong struggle
student stuff stumble style subject submit subway success such sudden suffer sugar suggest suit
summer sun sunny sunset super supply supreme sure surface surge surprise surround survey suspect
sustain swallow swamp swap swarm swear sweet swift swim swing switch sword symbol symptom syrup
system table tackle tag tail talent talk tank tape target task taste tattoo taxi teach team tell ten
tenant tennis tent term test text thank that theme then theory there they thing this thought three
thrive throw thumb thunder ticket tide tiger tilt timber time tiny tip tired tissue title toast
tobacco today toddler toe together toilet token tomato tomorrow tone tongue tonight tool tooth top
topic topple torch tornado tortoise toss total tourist toward tower town toy track trade traffic
tragic train transfer trap trash travel tray treat tree trend trial tribe trick trigger trim trip
trophy trouble truck true truly trumpet trust truth try tube tuition tumble tuna tunnel turkey turn
turtle twelve twenty twice twin twist two type typical ugly umbrella unable unaware uncle uncover
under undo unfair unfold unhappy uniform unique unit universe unknown unlock until unusual unveil
update upgrade uphold upon upper upset urban urge usage use used useful useless usual utility vacant
vacuum vague valid valley valve van vanish vapor various vast vault vehicle velvet vendor venture
venue verb verify version very vessel veteran viable vibrant vicious victory video view village
vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano volume vote
voyage wage wagon wait walk wall walnut want warfare warm warrior wash wasp waste water wave way
wealth weapon wear weasel weather web wedding weekend weird welcome west wet whale what wheat wheel
when where whip whisper wide width wife wild will win window wine wing wink winner winter wire
wisdom wise wish witness wolf woman wonder wood wool word work world worry worth wrap wreck wrestle
wrist write wrong yard year yellow you young youth zebra zero zone zoo
""".split()
BIP39_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
if hashlib.sha256(("\n".join(BIP39_WORDS) + "\n").encode()).hexdigest() != BIP39_SHA256:
    sys.exit("internal error: the built-in recovery word list is damaged; re-download wallet.py")
WORD_INDEX = {w: i for i, w in enumerate(BIP39_WORDS)}
PREFIX_INDEX = {w[:4]: i for i, w in enumerate(BIP39_WORDS)}     # first 4 letters are unique


def entropy_to_words(ent):
    bits = len(ent) * 8
    cs = bits // 32
    n = (int.from_bytes(ent, "big") << cs) | (hashlib.sha256(ent).digest()[0] >> (8 - cs))
    count = (bits + cs) // 11
    return [BIP39_WORDS[(n >> (11 * (count - 1 - i))) & 2047] for i in range(count)]


def words_to_entropy(phrase):
    """Parse a phrase (full words, or just their first 4 letters). Exits on any problem."""
    toks = unicodedata.normalize("NFKD", phrase).lower().replace(",", " ").split()
    toks = [t.split(".", 1)[-1] if t[:1].isdigit() else t for t in toks]   # allow "1.abandon"
    toks = [t for t in toks if t]
    if len(toks) not in (12, 15, 18, 21, 24):
        sys.exit(f"a recovery phrase has 12 or 24 words; got {len(toks)}")
    n = 0
    for pos, t in enumerate(toks, 1):
        i = WORD_INDEX.get(t)
        if i is None and len(t) >= 4 and t[:4] in PREFIX_INDEX \
                and BIP39_WORDS[PREFIX_INDEX[t[:4]]].startswith(t):
            i = PREFIX_INDEX[t[:4]]
        if i is None:
            sys.exit(f"word #{pos} ('{t}') is not in the recovery word list - check the spelling")
        n = (n << 11) | i
    total = 11 * len(toks)
    cs = total // 33
    ent = (n >> cs).to_bytes((total - cs) // 8, "big")
    if n & ((1 << cs) - 1) != hashlib.sha256(ent).digest()[0] >> (8 - cs):
        sys.exit("that phrase has a wrong word or the words are in the wrong order (checksum failed)")
    return ent


def entropy_to_key_seed(ent):
    phrase = unicodedata.normalize("NFKD", " ".join(entropy_to_words(ent)))
    bip39 = hashlib.pbkdf2_hmac("sha512", phrase.encode(), b"mnemonic", 2048)
    return hmac.new(b"ed25519 seed", bip39, hashlib.sha512).digest()[:32]   # SLIP-10 master key


def print_phrase(words):
    print("\n  YOUR RECOVERY PHRASE - write it down on paper, in order, and keep it secret:\n")
    for r in range(0, len(words), 4):
        print("   " + "".join(f"{i + 1:>2}. {w:<10}" for i, w in enumerate(words[r:r + 4], r)))
    print("\n  Anyone with these words can take your coins. Lose them AND the wallet file/password")
    print("  and the coins are gone forever. Never type them into a website or send them to anyone.\n")


def confirm_phrase(words):
    """Make the user prove they wrote it down (interactive terminals only)."""
    if not sys.stdin.isatty() or os.environ.get("NYAN_PASS"):
        return
    input("  Press Enter once you have written the words down...")
    print("\n" * 40)                                     # scroll the phrase off the screen
    for i in sorted(random.sample(range(len(words)), 3)):
        for attempt in range(3):
            got = input(f"  Type word #{i + 1}: ").strip().lower()
            if got == words[i] or (len(got) >= 4 and words[i].startswith(got)):
                break
            print("  That's not it, check your paper.")
        else:
            sys.exit("Phrase not confirmed. Nothing was saved; run 'new' again.")


# ---- wallet file: scrypt + ChaCha20-Poly1305 around the phrase's entropy ------------
SCRYPT_N = 2 ** 17     # ~128 MiB of memory per guess: makes password cracking expensive


def save_wallet(path, ent, pw):
    seed = entropy_to_key_seed(ent)
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        ser.Encoding.Raw, ser.PublicFormat.Raw).hex()
    addr, salt, nonce = make_addr(pub), os.urandom(16), os.urandom(12)
    key = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=8, p=1).derive(pw)
    ct = ChaCha20Poly1305(key).encrypt(nonce, ent, addr.encode())       # address is authenticated
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"version": 3, "address": addr, "pub": pub, "words": len(ent) * 3 // 4,
                   "nonce": nonce.hex(), "ct": ct.hex(),
                   "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": 8, "p": 1, "salt": salt.hex()}}, f)
    return addr


def wallet_new(path, nwords=24):
    if os.path.exists(path):
        sys.exit("refusing to overwrite existing wallet")
    ent = os.urandom(32 if nwords == 24 else 16)
    words = entropy_to_words(ent)
    print_phrase(words)
    confirm_phrase(words)
    pw = get_password(True)
    addr = save_wallet(path, ent, pw)
    print("New wallet:", addr)
    print("Restore anywhere with:  python3 wallet.py restore NEWFILE.json")


def wallet_restore(path):
    if os.path.exists(path):
        sys.exit("refusing to overwrite existing wallet")
    phrase = os.environ.get("NYAN_SEED") or getpass.getpass("Recovery phrase (hidden): ")
    ent = words_to_entropy(phrase)
    pw = get_password(True)
    print("Restored wallet:", save_wallet(path, ent, pw))


def _decrypt(w, pw):
    try:
        if w.get("version") not in (2, 3):
            sys.exit("unknown wallet format")
        k = w["kdf"]
        if (k["name"] != "scrypt" or not 2 ** 10 <= k["n"] <= 2 ** 22
                or k["r"] not in range(1, 33) or k["p"] not in range(1, 17)):
            sys.exit("unsupported wallet KDF parameters")
        key = Scrypt(salt=bytes.fromhex(k["salt"]), length=32, n=k["n"], r=k["r"], p=k["p"]).derive(pw)
        return ChaCha20Poly1305(key).decrypt(bytes.fromhex(w["nonce"]), bytes.fromhex(w["ct"]),
                                             w["address"].encode())
    except SystemExit:
        raise
    except Exception:
        sys.exit("wrong password (or wallet file corrupted)")


def wallet_unlock(w, pw):
    secret = _decrypt(w, pw)
    seed = entropy_to_key_seed(secret) if w["version"] == 3 else secret   # v2: raw key, no phrase
    key = Ed25519PrivateKey.from_private_bytes(seed)
    pub = key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()
    if make_addr(pub) != w["address"]:
        sys.exit("wallet file is inconsistent (address does not match key)")
    return key


def wallet_seed(path):
    with open(path) as f:
        w = json.load(f)
    if w.get("version") != 3:
        sys.exit("this wallet was made before recovery phrases existed; it has no phrase. "
                 "Make a new wallet and send your coins to it.")
    words = entropy_to_words(_decrypt(w, get_password()))
    print_phrase(words)


def parse_amount(s):
    try:
        v = Decimal(s) * COIN
        if v != v.to_integral_value() or v <= 0:
            raise ValueError
        return int(v)
    except (InvalidOperation, ValueError, OverflowError):
        sys.exit("amount must be positive with at most 8 decimals")


def send(args):
    with open(args.wallet) as f:
        w = json.load(f)
    key = wallet_unlock(w, get_password())
    if not valid_addr(args.to):
        sys.exit("invalid recipient address (checksum failed)")
    check_rules(args.node)
    nonce = http(args.node, f"/balance/{w['address']}")["next_nonce"]
    t = {"chain": CHAIN_ID, "from": w["address"], "pub": w["pub"], "to": args.to,
         "amount": parse_amount(args.amount), "fee": parse_amount(args.fee), "nonce": nonce}
    t["sig"] = key.sign(tx_body(t).encode()).hex()
    try:
        r = http(args.node, "/tx", t)
        print(r)
        if r.get("txid"):
            print(f"Check it with:  python3 wallet.py tx {r['txid']}")
    except urllib.error.HTTPError as e:
        sys.exit(f"rejected by node (HTTP {e.code}): bad nonce, insufficient funds, or invalid tx")


def show_history(target, node, limit):
    addr = target
    if os.path.exists(target):                       # a wallet file works too
        with open(target) as f:
            addr = json.load(f)["address"]
    if not valid_addr(addr):
        sys.exit("give an address (NYAN...) or a wallet file")
    r = http(node, f"/history/{addr}?limit={limit}")
    short = lambda a: "mining" if a == "COINBASE" else a[:14] + "…"
    print(f"{addr}\nbalance {r['balance']:.8f} NYAN  ·  {r['total']} confirmed entries  ·  chain height {r['tip']}")
    if r["pending"]:
        print("\nPending (waiting to be mined):")
        for t in r["pending"]:
            out = t["from"] == addr
            amt = -(t["amount"] + t["fee"]) if out else t["amount"]
            print(f"  {amt:+15.8f}  {'to ' + short(t['to']) if out else 'from ' + short(t['from'])}")
    print("\nConfirmed (newest first):" if r["confirmed"] else "\nNo confirmed payments yet.")
    for t in r["confirmed"]:
        if t["kind"] == "reward":
            amt, what = t["amount"], "mining reward"
        elif t["from"] == addr:
            amt = -t["fee"] if t["to"] == addr else -(t["amount"] + t["fee"])
            what = f"to {short(t['to'])} (fee {t['fee']:.8f})"
        else:
            amt, what = t["amount"], f"from {short(t['from'])}"
        print(f"  block {t['height']:>7}  {t['confirmations']:>6} conf  {amt:+15.8f}  {what}")
    if r["total"] > len(r["confirmed"]):
        print(f"  … {r['total'] - len(r['confirmed'])} older entries (use --limit)")


def cli_main():
    ap = argparse.ArgumentParser(description="NyanCoin wallet")
    ap.add_argument("--version", action="version", version=f"NyanCoin wallet {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    DEF = DEFAULT_NODE
    nw = sub.add_parser("new", help="create a wallet with a new recovery phrase")
    nw.add_argument("file"); nw.add_argument("--words", type=int, choices=[12, 24], default=24)
    sub.add_parser("restore", help="rebuild a wallet file from your recovery phrase").add_argument("file")
    sub.add_parser("seed", help="show the recovery phrase of a wallet (needs password)").add_argument("file")
    sub.add_parser("show").add_argument("file")
    hi = sub.add_parser("history", help="payments in/out of an address (or wallet file)")
    hi.add_argument("target"); hi.add_argument("--limit", type=int, default=20); hi.add_argument("--node", default=DEF)
    tx = sub.add_parser("tx", help="is this payment confirmed?"); tx.add_argument("txid"); tx.add_argument("--node", default=DEF)
    b = sub.add_parser("balance"); b.add_argument("address"); b.add_argument("--node", default=DEF)
    st = sub.add_parser("status"); st.add_argument("--node", default=DEF)
    c = sub.add_parser("checkpoint"); c.add_argument("--height", type=int); c.add_argument("--node", default=DEF)
    s = sub.add_parser("send"); s.add_argument("--wallet", required=True); s.add_argument("--to", required=True)
    s.add_argument("--amount", required=True); s.add_argument("--fee", default="0.0001")
    s.add_argument("--node", default=DEF)
    a = ap.parse_args()

    if a.cmd == "new":
        wallet_new(a.file, a.words)
    elif a.cmd == "restore":
        wallet_restore(a.file)
    elif a.cmd == "seed":
        wallet_seed(a.file)
    elif a.cmd == "show":
        print(json.load(open(a.file))["address"])
    elif a.cmd == "history":
        show_history(a.target, a.node, max(1, min(500, a.limit)))
    elif a.cmd == "tx":
        r = http(a.node, f"/tx/{a.txid.strip().lower()}")
        msg = {"pending": "pending: waiting to be mined",
               "confirmed": f"confirmed in block {r.get('height')} ({r.get('confirmations')} confirmations)",
               "unknown": "unknown to this node (never sent, expired, or dropped)"}
        print(msg.get(r.get("status"), r))
    elif a.cmd == "balance":
        print(http(a.node, f"/balance/{a.address}"))
    elif a.cmd == "status":
        print(http(a.node, "/info"))
    elif a.cmd == "checkpoint":
        h = a.height if a.height is not None else max(1, http(a.node, "/info")["height"] - 100)
        print(f'CHECKPOINTS = {{{h}: "{http(a.node, f"/blocks?start={h}&count=1")[0]["hash"]}"}}')
    else:
        send(a)


# ======================================================================
# GUI wallet code
# ======================================================================
import queue as _queue
import random as _random
import time as _time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

GUI_VERSION = "1.0.0"
DEFAULT_NODE = "https://inter.net.sh:8001#aacf9733d8a238bc0f8a62232e5ab5b804cd3fe80b32e90c58bd70ff52f1fc41"   # official seed
MIN_RELAY_FEE = 1000            # nodes refuse payments with a lower fee (0.00001 NYAN)
CONFIG = os.path.join(HOME, "gui.json")


class Exit(Exception):
    """A wallet function wanted to stop with a message (sys.exit) - show it instead."""


def call(fn, *a):
    try:
        return fn(*a)
    except SystemExit as e:
        raise Exit(str(e.code) if e.code not in (None, 0) else "stopped")


def explain(e):
    """Human-readable error for a dialog or the status line."""
    if isinstance(e, Exit):
        return str(e)
    if isinstance(e, urllib.error.HTTPError):
        extra = (" Usually: not enough balance, the fee is too low, or an earlier payment is still "
                 "being processed. Wait a moment and try again.") if e.code == 400 else ""
        return f"The node refused this (HTTP {e.code}).{extra}"
    if isinstance(e, urllib.error.URLError):
        r = str(e.reason)
        if "pin" in r or "CHANGED" in r or "non-public" in r:
            return f"Security check failed - not sending anything to this node.\n\n{r}"
        return f"Can't reach the node ({r}). Is it running, and is the node address right?"
    if isinstance(e, (OSError, TimeoutError)):
        return f"Can't reach the node ({e})."
    return f"{type(e).__name__}: {e}"


def describe(addr, t):
    """(signed amount, text) for one history entry, seen from `addr`."""
    if t.get("kind") == "reward":
        return t["amount"], "Mining reward"
    if t["from"] == addr:
        if t["to"] == addr:
            return -t["fee"], "To yourself"
        return -(t["amount"] + t["fee"]), f"To {short(t['to'])}   (fee {t['fee']:.8f})"
    return t["amount"], f"From {short(t['from'])}"


def short(a):
    return a[:12] + "…" + a[-6:]


def _load_cfg():
    try:
        with open(CONFIG) as f:
            c = json.load(f)
        return c if isinstance(c, dict) else {}
    except Exception:
        return {}


class App:
    def __init__(self, root):
        self.root = root
        root.title("NyanCoin Wallet")
        root.geometry("860x600")
        root.minsize(720, 500)
        st = ttk.Style()
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure("Title.TLabel", font=("TkDefaultFont", 18, "bold"))
        st.configure("Big.TLabel", font=("TkDefaultFont", 24, "bold"))
        st.configure("Muted.TLabel", foreground="#666666")
        st.configure("Warn.TLabel", foreground="#b00020")
        st.configure("Ok.TLabel", foreground="#0a7d32")
        self.cfg = _load_cfg()
        self.node = tk.StringVar(value=self.cfg.get("node", DEFAULT_NODE))
        self.q, self.busy = _queue.Queue(), 0
        self.wallet = self.wallet_path = self.frame = self.status = None
        self._auto_id, self.row_tx = None, {}
        root.after(100, self._poll)
        self.show_welcome()

    # ---------------------------------------------------------------- plumbing
    def run(self, task, done=None, fail=None):
        """Run `task` in a background thread so the window never freezes."""
        def work():
            try:
                res = (True, task())
            except BaseException as e:          # incl. SystemExit from wallet code
                res = (False, e if not isinstance(e, SystemExit) else Exit(str(e.code)))
            self.q.put((res, done, fail))
        self.busy += 1
        self.root.configure(cursor="watch")
        threading.Thread(target=work, daemon=True).start()

    def _poll(self):
        try:
            while True:
                (ok, val), done, fail = self.q.get_nowait()
                self.busy -= 1
                if not self.busy:
                    self.root.configure(cursor="")
                if ok:
                    if done:
                        done(val)
                elif fail:
                    fail(val)
                else:
                    messagebox.showerror("NyanCoin", explain(val), parent=self.root)
        except _queue.Empty:
            pass
        self.root.after(100, self._poll)

    def save_cfg(self):
        self.cfg["node"] = self.node_url()
        try:
            os.makedirs(HOME, exist_ok=True)
            with open(CONFIG, "w") as f:
                json.dump(self.cfg, f)
        except OSError:
            pass

    def node_url(self):
        return self.node.get().strip() or DEFAULT_NODE

    def new_frame(self):
        if self._auto_id:
            self.root.after_cancel(self._auto_id)
            self._auto_id = None
        if self.frame:
            self.frame.destroy()
        self.frame = ttk.Frame(self.root, padding=20)
        self.frame.pack(fill="both", expand=True)
        self.status = None
        return self.frame

    def set_status(self, text):
        if self.status is not None and self.status.winfo_exists():
            self.status.configure(text=text)

    def copy(self, text, msg):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.set_status(msg)

    def dialog(self, title):
        d = tk.Toplevel(self.root)
        d.title(title)
        d.transient(self.root)
        fr = ttk.Frame(d, padding=18)
        fr.pack(fill="both", expand=True)
        return d, fr

    def modal(self, d):
        d.update_idletasks()
        try:
            d.grab_set()
        except tk.TclError:
            pass
        self.root.wait_window(d)

    def ask_password(self, title, confirm=False):
        d, fr = self.dialog(title)
        d.resizable(False, False)
        ttk.Label(fr, text="Wallet password:").grid(row=0, column=0, sticky="w")
        p1 = ttk.Entry(fr, show="•", width=34)
        p1.grid(row=1, column=0, pady=4)
        p2 = None
        if confirm:
            ttk.Label(fr, text="Repeat password:").grid(row=2, column=0, sticky="w")
            p2 = ttk.Entry(fr, show="•", width=34)
            p2.grid(row=3, column=0, pady=4)
            ttk.Label(fr, text="At least 12 characters. A few random words works well.\n"
                               "It protects the wallet file on this computer.",
                      style="Muted.TLabel").grid(row=4, column=0, sticky="w")
        out = {}

        def ok(*_):
            v = p1.get()
            if confirm:
                if len(v) < 12:
                    return messagebox.showerror(title, "Use at least 12 characters.", parent=d)
                if v != p2.get():
                    return messagebox.showerror(title, "The two passwords don't match.", parent=d)
            elif not v:
                return
            out["pw"] = v
            d.destroy()
        bf = ttk.Frame(fr)
        bf.grid(row=5, column=0, pady=(12, 0), sticky="e")
        ttk.Button(bf, text="Cancel", command=d.destroy).pack(side="right")
        ttk.Button(bf, text="OK", command=ok).pack(side="right", padx=6)
        d.bind("<Return>", ok)
        d.bind("<Escape>", lambda *_: d.destroy())
        p1.focus_set()
        self.modal(d)
        return out.get("pw")

    def word_grid(self, parent, words):
        g = ttk.Frame(parent)
        for i, w in enumerate(words):
            ttk.Label(g, text=f"{i + 1:>2}. {w}", font=("TkFixedFont", 13), width=15).grid(
                row=i // 4, column=i % 4, sticky="w", padx=8, pady=3)
        return g

    # ----------------------------------------------------------------- welcome
    def show_welcome(self):
        self.wallet = self.wallet_path = None
        f = self.new_frame()
        ttk.Label(f, text="NyanCoin Wallet", style="Title.TLabel").pack(pady=(40, 4))
        ttk.Label(f, text="Your keys stay on this computer. The node only ever sees signed payments.",
                  style="Muted.TLabel").pack(pady=(0, 28))
        box = ttk.Frame(f)
        box.pack()
        last = self.cfg.get("last_wallet")
        if isinstance(last, str) and os.path.exists(last):
            ttk.Button(box, text=f"Open {os.path.basename(last)}",
                       command=lambda: self.open_wallet(last)).pack(fill="x", pady=4, ipady=5)
        for txt, cmd in (("Open a wallet file…", self.ask_open),
                         ("Create a new wallet", self.create_flow),
                         ("Restore from recovery phrase", self.restore_flow)):
            ttk.Button(box, text=txt, command=cmd, width=36).pack(fill="x", pady=4, ipady=5)
        nf = ttk.Frame(f)
        nf.pack(pady=(36, 0))
        ttk.Label(nf, text="Node:").pack(side="left")
        ttk.Entry(nf, textvariable=self.node, width=56).pack(side="left", padx=6)
        ttk.Label(f, text="Use your own node if you can. Add #PIN to the address to verify its identity.",
                  style="Muted.TLabel").pack(pady=(6, 0))

    def ask_open(self):
        p = filedialog.askopenfilename(parent=self.root, title="Open wallet file",
                                       filetypes=[("Wallet", "*.json"), ("All files", "*")])
        if p:
            self.open_wallet(p)

    def open_wallet(self, path):
        try:
            with open(path) as fh:
                w = json.load(fh)
            if not valid_addr(w.get("address")) or w.get("version") not in (2, 3):
                raise ValueError
        except Exception:
            return messagebox.showerror("Open wallet", "That isn't a NyanCoin wallet file.",
                                        parent=self.root)
        self.wallet, self.wallet_path = w, os.path.abspath(path)
        self.cfg["last_wallet"] = self.wallet_path
        self.save_cfg()
        self.show_main()

    def save_new(self, path, ent, pw):
        if os.path.exists(path):
            return messagebox.showerror("Save wallet", "A file with that name already exists. "
                                        "Choose a new name so nothing gets overwritten.", parent=self.root)
        self.run(lambda: save_wallet(path, ent, pw.encode()), lambda addr: self.open_wallet(path))

    # ------------------------------------------------------------------ create
    def create_flow(self):
        st = {"ent": os.urandom(32)}
        d, body = self.dialog("Create a new wallet")

        def clear():
            for c in body.winfo_children():
                c.destroy()

        def step_show():
            clear()
            d.unbind("<Return>")
            words = entropy_to_words(st["ent"])
            ttk.Label(body, text="Your recovery phrase", style="Title.TLabel").pack(anchor="w")
            ttk.Label(body, style="Warn.TLabel", justify="left", text=(
                "Write these words on paper, in order. They are the only way to get your coins back\n"
                "if you lose this computer or forget the password. Anyone who sees them can take your\n"
                "coins, so never photograph, email, or type them into a website.")).pack(anchor="w", pady=(4, 10))
            self.word_grid(body, words).pack(pady=6)
            opt = ttk.Frame(body)
            opt.pack(anchor="w", pady=4)
            nv = tk.IntVar(value=len(words))

            def regen():
                st["ent"] = os.urandom(32 if nv.get() == 24 else 16)
                step_show()
            ttk.Radiobutton(opt, text="24 words (recommended)", variable=nv, value=24, command=regen).pack(side="left")
            ttk.Radiobutton(opt, text="12 words", variable=nv, value=12, command=regen).pack(side="left", padx=12)
            ok = tk.BooleanVar()
            nxt = ttk.Button(body, text="Next", state="disabled", command=step_check)
            ttk.Checkbutton(body, text="I have written all the words down on paper", variable=ok,
                            command=lambda: nxt.configure(state="normal" if ok.get() else "disabled")
                            ).pack(anchor="w", pady=(12, 4))
            nxt.pack(anchor="e")

        def step_check():
            words = entropy_to_words(st["ent"])
            picks = sorted(_random.sample(range(len(words)), 3))
            clear()
            ttk.Label(body, text="Check your paper", style="Title.TLabel").pack(anchor="w")
            ttk.Label(body, text="Type these words from what you wrote down (the first 4 letters is enough).",
                      style="Muted.TLabel").pack(anchor="w", pady=(4, 12))
            g = ttk.Frame(body)
            g.pack(anchor="w")
            ents = {}
            for r, i in enumerate(picks):
                ttk.Label(g, text=f"Word #{i + 1}").grid(row=r, column=0, sticky="w", pady=3)
                e = ttk.Entry(g, width=18)
                e.grid(row=r, column=1, padx=8)
                ents[i] = e
            ents[picks[0]].focus_set()

            def check(*_):
                for i, e in ents.items():
                    t = e.get().strip().lower()
                    if not (t == words[i] or (len(t) >= 4 and words[i].startswith(t))):
                        return messagebox.showerror("Check your paper", f"Word #{i + 1} doesn't match. "
                                                    "Go back and check what you wrote.", parent=d)
                step_save()
            bf = ttk.Frame(body)
            bf.pack(fill="x", pady=(16, 0))
            ttk.Button(bf, text="Back", command=step_show).pack(side="left")
            ttk.Button(bf, text="Next", command=check).pack(side="right")
            d.bind("<Return>", check)

        def step_save():
            pw = self.ask_password("Set a wallet password", confirm=True)
            if not pw:
                return
            path = filedialog.asksaveasfilename(parent=d, title="Save wallet file", defaultextension=".json",
                                                initialfile="wallet.json", filetypes=[("Wallet", "*.json")])
            if not path:
                return
            ent = st["ent"]
            d.destroy()
            self.save_new(path, ent, pw)
        step_show()

    # ----------------------------------------------------------------- restore
    def restore_flow(self):
        d, fr = self.dialog("Restore from recovery phrase")
        ttk.Label(fr, text="Restore from recovery phrase", style="Title.TLabel").pack(anchor="w")
        ttk.Label(fr, text="Type or paste your 12 or 24 words, separated by spaces. The first 4 letters\n"
                           "of each word is enough. Only do this on a computer you trust.",
                  style="Muted.TLabel", justify="left").pack(anchor="w", pady=(4, 8))
        txt = tk.Text(fr, width=64, height=5, wrap="word", font=("TkFixedFont", 12))
        txt.pack(fill="x")
        status = ttk.Label(fr, text="", style="Muted.TLabel")
        status.pack(anchor="w", pady=6)

        def validate(*_):
            p = txt.get("1.0", "end").strip()
            if not p:
                status.configure(text="", style="Muted.TLabel")
                return None
            try:
                ent = call(words_to_entropy, p)
            except Exit as e:
                status.configure(text=str(e), style="Warn.TLabel")
                return None
            status.configure(text=f"Valid {len(ent) * 3 // 4}-word recovery phrase.", style="Ok.TLabel")
            return ent
        for ev in ("<KeyRelease>", "<<Paste>>", "<FocusOut>"):
            txt.bind(ev, lambda e: txt.after(10, validate))
        self.restore_validate = validate             # (used by the self-test)

        def go():
            ent = validate()
            if ent is None:
                return messagebox.showerror("Restore", status.cget("text") or "Enter your recovery phrase.",
                                            parent=d)
            pw = self.ask_password("Set a wallet password", confirm=True)
            if not pw:
                return
            path = filedialog.asksaveasfilename(parent=d, title="Save restored wallet", defaultextension=".json",
                                                initialfile="wallet.json", filetypes=[("Wallet", "*.json")])
            if not path:
                return
            txt.delete("1.0", "end")
            d.destroy()
            self.save_new(path, ent, pw)
        bf = ttk.Frame(fr)
        bf.pack(fill="x", pady=(8, 0))
        ttk.Button(bf, text="Cancel", command=d.destroy).pack(side="left")
        ttk.Button(bf, text="Restore", command=go).pack(side="right")
        txt.focus_set()
        self.restore_text = txt                     # (used by the self-test)

    # -------------------------------------------------------------------- main
    def show_main(self):
        w = self.wallet
        f = self.new_frame()
        top = ttk.Frame(f)
        top.pack(fill="x")
        left = ttk.Frame(top)
        left.pack(side="left", fill="x", expand=True)
        ttk.Label(left, text="Balance", style="Muted.TLabel").pack(anchor="w")
        self.bal = ttk.Label(left, text="…", style="Big.TLabel")
        self.bal.pack(anchor="w")
        self.pend_lbl = ttk.Label(left, text="", style="Muted.TLabel")
        self.pend_lbl.pack(anchor="w")
        ttk.Button(top, text="Refresh", command=lambda: self.refresh(loud=True)).pack(side="right", anchor="n")
        ar = ttk.Frame(f)
        ar.pack(fill="x", pady=(10, 0))
        ttk.Label(ar, text="Your address (to receive):").pack(side="left")
        self.addr_v = tk.StringVar(value=w["address"])
        ttk.Entry(ar, textvariable=self.addr_v, state="readonly", width=50, font=("TkFixedFont", 11)).pack(side="left", padx=6)
        ttk.Button(ar, text="Copy", command=lambda: self.copy(w["address"], "Address copied.")).pack(side="left")

        nb = ttk.Notebook(f)
        nb.pack(fill="both", expand=True, pady=(14, 0))
        self.nb = nb
        # history
        ht = ttk.Frame(nb, padding=8)
        nb.add(ht, text="History")
        tv = ttk.Treeview(ht, columns=("status", "block", "amount", "details"), show="headings", height=12)
        for c, t, wd, anc in (("status", "Status", 130, "w"), ("block", "Block", 70, "e"),
                              ("amount", "Amount (NYAN)", 150, "e"), ("details", "Details", 400, "w")):
            tv.heading(c, text=t)
            tv.column(c, width=wd, anchor=anc, stretch=(c == "details"))
        sb = ttk.Scrollbar(ht, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=sb.set)
        tv.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")
        tv.tag_configure("in", foreground="#0a7d32")
        tv.tag_configure("out", foreground="#b00020")
        tv.tag_configure("pending", foreground="#8a6d00")
        tv.bind("<Double-1>", self._copy_txid)
        self.tv = tv
        # send
        sf = ttk.Frame(nb, padding=18)
        nb.add(sf, text="Send")
        self.to_v, self.amt_v, self.fee_v = tk.StringVar(), tk.StringVar(), tk.StringVar(value="0.0001")
        for r, (lbl, var, wd, hint) in enumerate((
                ("To address", self.to_v, 52, "Starts with NYAN. Typos are detected automatically."),
                ("Amount (NYAN)", self.amt_v, 20, "Up to 8 decimal places."),
                ("Fee (NYAN)", self.fee_v, 20, "Goes to the miner. Minimum 0.00001; 0.0001 is normal."))):
            ttk.Label(sf, text=lbl).grid(row=r * 2, column=0, sticky="w", pady=(6, 0))
            ttk.Entry(sf, textvariable=var, width=wd, font=("TkFixedFont", 11)).grid(row=r * 2, column=1, sticky="w",
                                                                                    padx=8, pady=(6, 0))
            ttk.Label(sf, text=hint, style="Muted.TLabel").grid(row=r * 2 + 1, column=1, sticky="w", padx=8)
        ttk.Button(sf, text="Send…", command=self.send_flow).grid(row=6, column=1, sticky="w", padx=8, pady=(16, 0))
        ttk.Label(sf, text="You'll see a summary and be asked for your password before anything is sent.",
                  style="Muted.TLabel").grid(row=7, column=1, sticky="w", padx=8, pady=(6, 0))
        # settings
        cf = ttk.Frame(nb, padding=18)
        nb.add(cf, text="Settings")
        ttk.Label(cf, text="Node address").grid(row=0, column=0, sticky="w")
        ttk.Entry(cf, textvariable=self.node, width=60).grid(row=1, column=0, sticky="w", pady=4)
        ttk.Button(cf, text="Save & test", command=self.test_node).grid(row=1, column=1, padx=8)
        ttk.Label(cf, text="Add #PIN (from the node's startup message) to verify the node's identity "
                           "on every connection.", style="Muted.TLabel").grid(row=2, column=0, columnspan=2, sticky="w")
        ttk.Separator(cf).grid(row=3, column=0, columnspan=2, sticky="ew", pady=14)
        ttk.Button(cf, text="Show recovery phrase…", command=self.show_phrase).grid(row=4, column=0, sticky="w")
        ttk.Label(cf, text=f"Wallet file: {self.wallet_path}", style="Muted.TLabel").grid(
            row=5, column=0, columnspan=2, sticky="w", pady=(10, 0))
        ttk.Button(cf, text="Close wallet", command=self.show_welcome).grid(row=6, column=0, sticky="w", pady=(14, 0))

        self.status = ttk.Label(f, text="Connecting…", style="Muted.TLabel")
        self.status.pack(anchor="w", pady=(8, 0))
        self.refresh()
        self._auto_id = self.root.after(10000, self._auto)

    def _auto(self):
        self._auto_id = None
        if self.wallet:
            if not self.busy:
                self.refresh()
            self._auto_id = self.root.after(10000, self._auto)

    def refresh(self, loud=False):
        if not self.wallet:
            return
        addr, node = self.wallet["address"], self.node_url()

        def done(r):
            if self.wallet and self.wallet["address"] == addr:
                self.render(r)
                self.set_status(f"Connected to {node.split('#')[0]}  ·  chain height {r['tip']}  ·  "
                                f"updated {_time.strftime('%H:%M:%S')}  ·  double-click a payment to copy its ID")

        def fail(e):
            self.set_status(explain(e).split("\n")[0])
            if loud:
                messagebox.showerror("NyanCoin", explain(e), parent=self.root)
        self.run(lambda: http(node, f"/history/{addr}?limit=200"), done, fail)

    def render(self, r):
        addr, tv = self.wallet["address"], self.tv
        self.bal.configure(text=f"{r['balance']:,.8f} NYAN")
        pin = sum(t["amount"] for t in r["pending"] if t["to"] == addr and t["from"] != addr)
        pout = sum(t["amount"] + t["fee"] for t in r["pending"] if t["from"] == addr)
        parts = ([f"+{pin:,.8f} incoming"] if pin else []) + ([f"-{pout:,.8f} outgoing"] if pout else [])
        self.pend_lbl.configure(text=("Pending: " + ", ".join(parts)) if parts else "")
        tv.delete(*tv.get_children())
        self.row_tx = {}
        for t in r["pending"]:
            amt, what = describe(addr, t)
            self.row_tx[tv.insert("", "end", values=("Pending", "", f"{amt:+,.8f}", what), tags=("pending",))] = t["txid"]
        for t in r["confirmed"]:
            amt, what = describe(addr, t)
            c = t["confirmations"]
            stt = f"{c} confirmation{'s' if c != 1 else ''}" if c < 100 else "Confirmed"
            item = tv.insert("", "end", values=(stt, t["height"], f"{amt:+,.8f}", what),
                             tags=("in" if amt >= 0 else "out",))
            if t.get("txid"):
                self.row_tx[item] = t["txid"]
        if not r["pending"] and not r["confirmed"]:
            tv.insert("", "end", values=("", "", "", "No payments yet. Share your address to receive coins."))

    def _copy_txid(self, _ev):
        sel = self.tv.selection()
        if sel and sel[0] in self.row_tx:
            self.copy(self.row_tx[sel[0]], "Transaction ID copied.")

    def test_node(self):
        self.save_cfg()
        node = self.node_url()
        self.run(lambda: http(node, "/info"),
                 lambda r: (self.set_status(f"Node OK  ·  chain height {r['height']}"), self.refresh()))

    # -------------------------------------------------------------------- send
    def send_flow(self):
        err = lambda m: messagebox.showerror("Send", m, parent=self.root)
        to = self.to_v.get().strip()
        if not valid_addr(to):
            return err("That address isn't valid. Make sure it was copied completely: NyanCoin addresses "
                       "start with NYAN, and a built-in check catches typos.")
        try:
            amount = call(parse_amount, self.amt_v.get().strip())
        except Exit:
            return err("Enter an amount greater than 0, with at most 8 decimal places.")
        try:
            fee = call(parse_amount, self.fee_v.get().strip())
        except Exit:
            return err("Enter a fee, for example 0.0001.")
        if fee < MIN_RELAY_FEE:
            return err("The fee must be at least 0.00001 NYAN, or nodes won't pass the payment on.")
        if to == self.wallet["address"] and not messagebox.askyesno(
                "Send", "That's your own address. Send to yourself anyway? (You only pay the fee.)",
                parent=self.root):
            return
        summary = (f"Send {amount / COIN:,.8f} NYAN\nto {to}\n\nFee: {fee / COIN:.8f} NYAN\n"
                   f"Total: {(amount + fee) / COIN:,.8f} NYAN\n\nPayments can't be reversed.")
        if not messagebox.askokcancel("Confirm payment", summary, icon="warning", parent=self.root):
            return
        pw = self.ask_password("Unlock wallet to send")
        if pw:
            self.send(to, amount, fee, pw)

    def send(self, to, amount, fee, pw):
        w, node = self.wallet, self.node_url()

        def task():
            call(check_rules, node)
            key = call(wallet_unlock, w, pw.encode())
            nonce = http(node, f"/balance/{w['address']}")["next_nonce"]
            t = {"chain": CHAIN_ID, "from": w["address"], "pub": w["pub"], "to": to,
                 "amount": amount, "fee": fee, "nonce": nonce}
            t["sig"] = key.sign(tx_body(t).encode()).hex()
            return http(node, "/tx", t)

        def done(r):
            if r.get("ok"):
                self.to_v.set("")
                self.amt_v.set("")
                self.nb.select(0)
                self.refresh()
                messagebox.showinfo("Sent", "Payment sent. It shows as Pending until a miner includes it "
                                    f"in a block.\n\nTransaction ID:\n{r['txid']}", parent=self.root)
            else:
                messagebox.showerror("Send", f"The node didn't accept it ({r.get('result')}).", parent=self.root)
        self.run(task, done)

    # ------------------------------------------------------------------ phrase
    def show_phrase(self):
        w = self.wallet
        if w.get("version") != 3:
            return messagebox.showinfo("Recovery phrase", "This wallet was made before recovery phrases existed, "
                                       "so it doesn't have one. Create a new wallet and send your coins to it.",
                                       parent=self.root)
        pw = self.ask_password("Unlock to show recovery phrase")
        if not pw:
            return

        def done(words):
            d, fr = self.dialog("Recovery phrase")
            ttk.Label(fr, text="Recovery phrase", style="Title.TLabel").pack(anchor="w")
            ttk.Label(fr, text="Make sure nobody can see your screen. Anyone with these words can take your coins.",
                      style="Warn.TLabel").pack(anchor="w", pady=(4, 10))
            self.word_grid(fr, words).pack(pady=6)
            ttk.Button(fr, text="Close", command=d.destroy).pack(anchor="e", pady=(10, 0))
        self.run(lambda: entropy_to_words(call(_decrypt, w, pw.encode())), done)


def main():
    if any(a in ("-h", "--help") for a in sys.argv[1:]):
        print(__doc__)
        return
    if "--version" in sys.argv[1:]:
        print(f"NyanCoin GUI wallet {GUI_VERSION}")
        return
    try:
        root = tk.Tk()
    except tk.TclError as e:
        sys.exit(f"Can't open a window ({e}). The GUI needs a desktop; use wallet.py on servers.")
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
