#!/usr/bin/env python3
"""NyanCoin wallet & client tools. Keys never leave this program; nodes only see signed txs.

  python3 wallet.py new wallet.json [--words 12]  create a wallet + 24-word recovery phrase
  python3 wallet.py restore wallet.json          rebuild a wallet from its recovery phrase
  python3 wallet.py seed wallet.json             show the recovery phrase again (needs password)
  python3 wallet.py show wallet.json             print its address
  python3 wallet.py balance NYAN... [--node URL]
  python3 wallet.py history wallet.json          payments in/out, pending + confirmations
  python3 wallet.py tx TXID                      is a payment confirmed?
  python3 wallet.py send --wallet wallet.json --to NYAN... --amount 1.5 [--fee 0.0001] [--node URL]
  python3 wallet.py status [--node URL]          node height / work / tip
  python3 wallet.py checkpoint [--height H]      print a CHECKPOINTS line for nyancore.py

Wallet file: scrypt (2^17, ~128 MiB/guess) + ChaCha20-Poly1305, 12+ char passphrase.
NYAN_SEED can supply the phrase to 'restore' in scripts.
Set NYAN_PASS to skip the prompt (convenient for scripts, but visible to local processes).
"""
import argparse, getpass, json, os, sys, urllib.error
from decimal import Decimal, InvalidOperation

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from nyancore import *          # shared rules + pinned-TLS client

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


def main():
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


if __name__ == "__main__":
    main()
