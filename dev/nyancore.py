"""nyancore - shared rules of NyanCoin: consensus, transactions, blocks, and the
pinned-TLS client used by the node, miner and wallet.  (Not run directly.)

Consensus / security
  * Ed25519 signatures; address = hash(pubkey) + checksum (typo protection)
  * Account nonces (replay protection) + chain id; integer amounts only
  * Strict schema/type checks; every block re-validated; fork choice = most work
  * Difficulty retarget + floor, median-time-past rule, halving reward, fees, size caps
  * Optional CHECKPOINTS pin old history permanently
Encryption
  * All traffic is TLS 1.2+/1.3. No certificate authority: a node's identity is the
    SHA-256 of its TLS public key (its "pin"). Use https://host:port#PIN, or
    trust-on-first-use like SSH (~/.nyancoin/known_hosts.json; a changed key is refused).
"""
import hashlib, http.client, ipaddress, json, os, socket, ssl, threading, time
import urllib.error, urllib.request
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# ---------------------------------------------------------------- consensus
CHAIN_ID = "nyancoin-2"          # v2: slower supply schedule (new chain)
COIN = 10 ** 8                  # smallest unit = 1e-8 NYAN
REWARD0 = 1 * COIN             # 1 NYAN per block...
HALVING = 10_500_000           # ...halving every 10.5M blocks (~3.3 years at 10 s) -> 21M max
INIT_BITS, MIN_BITS, MAX_BITS = 20, 20, 60    # difficulty can never collapse below INIT
RETARGET, TARGET_SPACING = 10, 10      # blocks, seconds
MAX_TXS, MAX_FUTURE, MAX_INT = 500, 7200, 2 ** 53
MAX_BLOCK_BYTES = 1_000_000
CHECKPOINTS = {}   # height -> block hash; history before these can never be rewritten
                   # (generate with:  python3 nyancoin.py checkpoint --node URL)

# ------------------------------------------------------------ runtime globals
NET_GUARD = False       # set by the node: refuse unpinned peers on private/loopback IPs
HOME = os.environ.get("NYAN_HOME") or os.path.expanduser("~/.nyancoin")


def H(x):
    return hashlib.sha256(x if isinstance(x, bytes) else x.encode()).hexdigest()


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"))


def make_addr(pub_hex):
    body = H(bytes.fromhex(pub_hex))[:40]
    return "NYAN" + body + H(body)[:4]


def valid_addr(a):
    return (isinstance(a, str) and len(a) == 48 and a.startswith("NYAN")
            and all(c in "0123456789abcdef" for c in a[4:])
            and H(a[4:44])[:4] == a[44:])


# ------------------------------------------------------------ transactions
TX_KEYS = {"chain", "from", "pub", "to", "amount", "fee", "nonce", "sig"}


def tx_body(t):
    return canon({k: t[k] for k in ("chain", "from", "to", "amount", "fee", "nonce")})


def txid(t):
    return H(canon(t))


def check_tx(t):
    """Stateless validity: schema, types, address binding, signature."""
    try:
        if not isinstance(t, dict) or set(t) != TX_KEYS or t["chain"] != CHAIN_ID:
            return False
        for k in ("amount", "fee", "nonce"):
            if type(t[k]) is not int or not 0 <= t[k] <= MAX_INT:
                return False
        if t["amount"] <= 0 or not valid_addr(t["to"]) or t["from"] != make_addr(t["pub"]):
            return False
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(t["pub"])).verify(
            bytes.fromhex(t["sig"]), tx_body(t).encode())
        return True
    except Exception:
        return False


class State:
    def __init__(self):
        self.bal, self.nonce = {}, {}

    def copy(self):
        s = State()
        s.bal, s.nonce = dict(self.bal), dict(self.nonce)
        return s


def apply_tx(s, t):
    f, cost = t["from"], t["amount"] + t["fee"]
    if t["nonce"] != s.nonce.get(f, 0) or s.bal.get(f, 0) < cost:
        return False
    s.bal[f] -= cost
    s.bal[t["to"]] = s.bal.get(t["to"], 0) + t["amount"]
    s.nonce[f] = t["nonce"] + 1
    return True


# ------------------------------------------------------------------ blocks
BLOCK_KEYS = {"index", "prev", "time", "bits", "txs", "nonce", "hash"}


def header_prefix(b):
    return canon({k: b[k] for k in ("index", "prev", "time", "bits", "txs")}) + "|"


def block_hash(b):
    return H(header_prefix(b) + str(b["nonce"]))


def meets(h, bits):
    return int(h, 16) < (1 << (256 - bits))


def reward(height):
    return REWARD0 >> (height // HALVING)


def make_genesis():
    g = {"index": 0, "prev": "0" * 64, "time": 1762905600, "bits": INIT_BITS,
         "txs": [], "nonce": 0}
    g["hash"] = block_hash(g)
    return g


GENESIS = make_genesis()


def median_time(chain):
    ts = sorted(b["time"] for b in chain[-11:])
    return ts[len(ts) // 2]


def expected_bits(chain, index):
    prev = chain[index - 1]
    if index % RETARGET:
        return prev["bits"]
    span = prev["time"] - chain[index - RETARGET]["time"]
    exp, bits = (RETARGET - 1) * TARGET_SPACING, prev["bits"]
    if span < exp // 2:
        bits += 1
    elif span > exp * 2:
        bits -= 1
    return min(max(bits, MIN_BITS), MAX_BITS)


def apply_block(chain, s, b):
    """Validate b on top of `chain`; on success mutate state s. Atomic."""
    try:
        prev = chain[-1]
        if not isinstance(b, dict) or set(b) != BLOCK_KEYS:
            return False
        for k in ("index", "time", "bits", "nonce"):
            if type(b[k]) is not int or b[k] < 0:
                return False
        if (len(canon(b)) > MAX_BLOCK_BYTES or b["index"] != prev["index"] + 1
                or b["prev"] != prev["hash"] or b["time"] <= median_time(chain)
                or b["time"] > time.time() + MAX_FUTURE
                or b["bits"] != expected_bits(chain, b["index"])
                or b["hash"] != block_hash(b) or not meets(b["hash"], b["bits"])
                or CHECKPOINTS.get(b["index"], b["hash"]) != b["hash"]):
            return False
        txs = b["txs"]
        if not isinstance(txs, list) or not 1 <= len(txs) <= MAX_TXS + 1:
            return False
        cb, rest = txs[0], txs[1:]
        if (not isinstance(cb, dict) or set(cb) != {"from", "to", "amount", "height"}
                or cb["from"] != "COINBASE" or cb["height"] != b["index"]
                or not valid_addr(cb["to"]) or type(cb["amount"]) is not int):
            return False
        t, seen, fees = s.copy(), set(), 0
        for x in rest:
            if not check_tx(x) or txid(x) in seen or not apply_tx(t, x):
                return False
            seen.add(txid(x))
            fees += x["fee"]
        if cb["amount"] != reward(b["index"]) + fees:
            return False
        t.bal[cb["to"]] = t.bal.get(cb["to"], 0) + cb["amount"]
        s.bal, s.nonce = t.bal, t.nonce
        return True
    except Exception:
        return False


def replay(blocks):
    """Validate from genesis; returns (chain, state, work) for the valid prefix."""
    if not isinstance(blocks, list) or not blocks or blocks[0] != GENESIS:
        return None
    chain, s, work = [GENESIS], State(), 0
    for b in blocks[1:]:
        if not apply_block(chain, s, b):
            break
        chain.append(b)
        work += 1 << b["bits"]
    return chain, s, work



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
