#!/usr/bin/env python3
"""NyanCoin node: keeps and verifies the chain, relays txs/blocks to peers, serves the API.
It does NOT mine (run miner.py for that) and holds no wallet keys (see wallet.py).

  python3 node.py --port 8001                                   # local / outbound-only node
  python3 node.py --port 8001 --public-url https://IP:8001      # reachable seed (prints its pin)
  python3 node.py --port 8001 --peers "https://seed.example.com:8001#PIN"

Networking
  * Works behind NAT: nodes poll peers, so no port forwarding is needed to *follow* the chain.
    Forward a port + --public-url only if you want inbound peers.
  * Gossip discovery (pins travel with peers), periodic refresh, self re-announce, saved peers
  * Peer health scoring: dead peers evicted, misbehaving peers/IPs banned
  * Incremental sync with fork-point search + reorgs (max 100 deep; orphaned txs re-queued)
  * Hardening: per-IP rate limit, connection caps, size limits, slow-client timeouts,
    private-IP peers refused (checked on the real connected address), max 2 untrusted peers
    per /16 (anti-eclipse), liars banned, relay fee floor + mempool eviction/expiry,
    fsync + torn-write recovery.
IPv4 + IPv6: with --public-url the node listens on both (dual-stack "::"), falling back to
IPv4-only if the machine has no IPv6. IPv6 peers look like https://[2001:db8::1]:8001#PIN.
Open https://127.0.0.1:<port>/ for a live status page (accept the self-signed cert).

Self-contained: this single file is all you need (plus: pip install cryptography).
Consensus rules are locked: the file refuses to start if its shared-rules section is edited.
"""
import argparse, datetime, hashlib, html, http.client, ipaddress, json, os, random, socket, ssl
import sys, threading, time, urllib.error, urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509.oid import NameOID

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
# <<< SHARED RULES END

# ---- rules lock: refuse to run if the shared rules above were modified ----------------
EXPECTED_SHARED_HASH = "6dd1d4c699ba40bb6e5374a90da48d47837ebb525027fedcbe7a0285e4d0cba0"


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
# node code
# ======================================================================
# ---- editable: official checkpoints (height -> block hash). Get a line with
#      python3 wallet.py checkpoint --node URL   and add it here ONLY if the network agrees.
#      Blocks that contradict a checkpoint are rejected; history before it can never be rewritten.
CHECKPOINTS = {}


VERSION = "1.0.0"

# ------------------------------------------------------------ node policy
MAX_BODY, MAX_MEMPOOL, MAX_PEERS = 1_000_000, 5000, 32
BATCH, MAX_REORG, RATE_LIMIT = 200, 100, 600    # RATE_LIMIT: requests/min/IP
MIN_FEE = 1000                 # relay policy: min fee (0.00001 NYAN) vs mempool spam
MEMPOOL_TTL = 86_400           # drop unconfirmed txs after 24h
MAX_CONN, MAX_CONN_PER_IP = 200, 32     # concurrent connections (global / per IP)
PEERS_PER_GROUP = 2            # max untrusted peers per /16 network (anti-eclipse)
# Hard-coded bootstrap nodes WITH their TLS key pin (printed when a node starts):
#   SEEDS = ["https://seed.example.com:8001#<64-hex-pin>"]
SEEDS = ["https://inter.net.sh:8001#aacf9733d8a238bc0f8a62232e5ab5b804cd3fe80b32e90c58bd70ff52f1fc41"]   # official seed (inter.net.sh), pinned


def ip_key(ip):
    """Rate-limit identity: an IPv4 address, or a whole IPv6 /64 (one home/server usually gets a /64)."""
    try:
        a = norm_ip(ip)
    except ValueError:
        return str(ip)
    return str(a) if a.version == 4 else str(ipaddress.ip_network(f"{a}/64", strict=False))


INSECURE = False        # --insecure: plain-HTTP node & peers (testing / behind a proxy)


def ensure_cert(data_dir, extra_host=None):
    """Self-signed ECDSA P-256 cert, created once. Returns (keyfile, certfile, pin)."""
    kp, cp = os.path.join(data_dir, "tls.key"), os.path.join(data_dir, "tls.crt")
    if not (os.path.exists(kp) and os.path.exists(cp)):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "nyancoin-node")])
        san = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
               x509.IPAddress(ipaddress.ip_address("::1"))]
        if extra_host:
            try:
                san.append(x509.IPAddress(ipaddress.ip_address(extra_host)))
            except ValueError:
                san.append(x509.DNSName(extra_host))
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=3650))
                .add_extension(x509.SubjectAlternativeName(san), critical=False)
                .sign(key, hashes.SHA256()))
        fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
        with open(cp, "wb") as f:
            f.write(cert.public_bytes(ser.Encoding.PEM))
    with open(cp, "rb") as f:
        pin = spki_pin(x509.load_pem_x509_certificate(f.read()).public_bytes(ser.Encoding.DER))
    return kp, cp, pin


class TLSServer(ThreadingHTTPServer):
    ctx = None
    sem = threading.BoundedSemaphore(MAX_CONN)
    per_ip, ip_lock = {}, threading.Lock()

    def process_request(self, request, client_address):
        ip = ip_key(client_address[0])
        with self.ip_lock:
            n = self.per_ip.get(ip, 0)
            full = n >= MAX_CONN_PER_IP or not self.sem.acquire(blocking=False)
            if not full:
                self.per_ip[ip] = n + 1
        if full:                               # connection flood: drop immediately
            return self.shutdown_request(request)
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.ip_lock:
                ip = ip_key(client_address[0])
                self.per_ip[ip] = self.per_ip.get(ip, 1) - 1
                if self.per_ip[ip] <= 0:
                    del self.per_ip[ip]
            self.sem.release()

    def get_request(self):
        s, addr = super().get_request()
        if self.ctx:   # handshake happens lazily in the handler thread (can't stall accept)
            s = self.ctx.wrap_socket(s, server_side=True, do_handshake_on_connect=False)
        return s, addr

    def handle_error(self, request, client_address):
        pass


class TLSServer6(TLSServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        try:                                            # accept IPv4 too (dual-stack)
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except (OSError, AttributeError):
            pass
        super().server_bind()


def make_server(host, port, handler):
    return (TLSServer6 if ":" in host else TLSServer)((host, port), handler)


def valid_peer(u):
    """https://host:port, https://1.2.3.4:port or https://[2001:db8::1]:port"""
    if not isinstance(u, str) or len(u) > 250:
        return False
    if not (u.startswith("https://") or (INSECURE and u.startswith("http://"))):
        return False
    try:
        p = urlsplit(u)
        return bool(p.hostname) and p.port is not None
    except ValueError:
        return False



# -------------------------------------------------------------------- node
class Node:
    def __init__(self, data_dir, peers, self_url, allow_local=False, tick=10,
                 max_reorg=MAX_REORG):
        self.lock = threading.RLock()
        os.makedirs(data_dir, exist_ok=True)
        self.chain_path = os.path.join(data_dir, "chain.jsonl")
        self.peers_path = os.path.join(data_dir, "peers.json")
        self.self_url, self.allow_local = self_url, allow_local
        self.tick, self.max_reorg = tick, max_reorg
        self.blocks, self.state, self.work = [GENESIS], State(), 0
        self.mempool, self.peers = {}, {}
        self.rate, self.bad = {}, {}
        self.syncing, self.tls_pin, self.seen = False, None, {}
        self.boot = [p for p in peers if valid_peer(p)] + SEEDS
        self._load()
        self._reindex()

    # --- persistence
    def _load(self):
        try:
            saved, torn = [], False
            with open(self.chain_path) as f:
                for line in f:
                    try:
                        saved.append(json.loads(line))
                    except ValueError:
                        torn = True                # torn write after a crash: keep good prefix
                        break
            res = replay(saved)
            if res:
                self.blocks, self.state, self.work = res
                if torn or len(self.blocks) != len(saved):
                    print("! repaired stored chain (dropped torn/invalid tail)")
                    self.rewrite()
        except FileNotFoundError:
            self.rewrite()
        except Exception:
            print("! stored chain unreadable; starting fresh")
            self.rewrite()
        try:
            with open(self.peers_path) as f:
                for u in json.load(f):
                    self.add_peer(u)
        except Exception:
            pass

    def rewrite(self):
        tmp = self.chain_path + ".tmp"
        with open(tmp, "w") as f:
            for b in self.blocks:
                f.write(json.dumps(b) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.chain_path)

    def save_peers(self):
        with self.lock:
            urls = [u + ("#" + p["pin"] if p["pin"] else "") for u, p in self.peers.items()]
        with open(self.peers_path, "w") as f:
            json.dump(urls, f)

    # --- peers (keyed by base URL; optional TLS pin kept alongside)
    def add_peer(self, url, trusted=False, group=None):
        base, _, pin = url.partition("#")
        with self.lock:
            if (not valid_peer(base) or base == self.self_url or base in self.peers
                    or len(self.peers) >= MAX_PEERS):
                return False
            if (group and not trusted and not self.allow_local and
                    sum(1 for p in self.peers.values() if p.get("group") == group) >= PEERS_PER_GROUP):
                return False                       # anti-eclipse: diversify networks
            self.peers[base] = {"fails": 0, "ban": 0, "trusted": trusted, "pin": pin, "group": group}
            return True

    def peer_list(self):
        """Live peers with the TLS pin we know for each (so others can skip TOFU)."""
        with self.lock:
            return [{"url": u, "pin": p["pin"] or known_pin(u)} for u, p in self.peers.items()
                    if p["ban"] < time.time()]

    def live_peers(self):
        now = time.time()
        with self.lock:
            return [u for u, p in self.peers.items() if p["ban"] < now]

    def ban_peer(self, url, secs=600):
        with self.lock:
            if url in self.peers and not self.peers[url]["trusted"]:
                self.peers[url]["ban"] = time.time() + secs

    def rpc(self, peer, path, obj=None, timeout=8):
        pin = (self.peers.get(peer) or {}).get("pin")
        try:
            r = http(peer + ("#" + pin if pin else ""), path, obj, timeout)
        except Exception:
            with self.lock:
                p = self.peers.get(peer)
                if p:
                    p["fails"] += 1
                    if p["fails"] >= 5 and not p["trusted"]:
                        del self.peers[peer]
            raise
        with self.lock:
            if peer in self.peers:
                self.peers[peer]["fails"] = 0
        return r

    def consider_peer(self, url, trusted=False, pin=""):
        """Verify then add a peer (run in a thread: does DNS + network)."""
        base, _, p0 = url.partition("#")
        pin = p0 or (pin if isinstance(pin, str) and len(pin) == 64 else "") or known_pin(base)
        full = base + ("#" + pin if pin else "")
        if base in self.peers or not valid_peer(base) or base == self.self_url:
            return
        ip = resolve(base)
        if not trusted and not self.allow_local:
            try:
                if not (ip and norm_ip(ip).is_global):
                    return
            except ValueError:
                return
        try:
            info = http(full, "/info", timeout=5)      # TLS identity verified against pin
        except Exception:
            return
        if (info.get("chain") == CHAIN_ID and info.get("genesis") == GENESIS["hash"]
                and info.get("rules") == RULES):
            self.add_peer(full, trusted, net_group(ip))

    def _async(self, fn, *a):
        threading.Thread(target=fn, args=a, daemon=True).start()

    def broadcast(self, path, obj):
        def send(p):
            try:
                self.rpc(p, path, obj, timeout=5)
            except Exception:
                pass
        for p in self.live_peers():
            self._async(send, p)

    def announce_self(self):
        if self.self_url:
            for p in self.live_peers():
                self._async(lambda p=p: self._try(p, "/peer", {"url": self.self_url, "pin": self.tls_pin or ""}))

    def _try(self, p, path, obj=None):
        try:
            return self.rpc(p, path, obj, timeout=5)
        except Exception:
            return None

    def refresh_peers(self):
        live = self.live_peers()
        for p in random.sample(live, min(3, len(live))):
            lst = self._try(p, "/peers")
            if isinstance(lst, list):
                for q in lst[:MAX_PEERS]:
                    if isinstance(q, dict) and isinstance(q.get("url"), str):
                        self.consider_peer(q["url"], pin=str(q.get("pin", "")))
                    elif isinstance(q, str):
                        self.consider_peer(q)
        if not self.live_peers():
            for u in self.boot:
                self.add_peer(u, trusted=True)

    # --- abuse control
    def check_ip(self, ip):
        now = time.time()
        with self.lock:
            b = self.bad.get(ip)
            if b and b[1] > now:
                return False
            q = self.rate.setdefault(ip, deque())
            while q and q[0] < now - 60:
                q.popleft()
            if len(q) >= RATE_LIMIT:
                return False
            q.append(now)
            if len(self.rate) > 10000:
                self.rate.clear()
        return True

    def strike(self, ip, n=1):
        with self.lock:
            c, until = self.bad.get(ip, (0, 0))
            c += n
            if c >= 20:
                c, until = 0, time.time() + 600
            self.bad[ip] = (c, until)

    # --- transactions: "ok" | "dup" | "bad"
    def add_tx(self, t):
        """"ok" | "dup" | "reject" (valid but unacceptable now) | "bad" (malformed/forged)"""
        with self.lock:
            if not check_tx(t):
                return "bad"
            i = txid(t)
            if i in self.mempool:
                return "dup"
            if t["fee"] < MIN_FEE:
                return "reject"
            tmp = self.state.copy()
            for m in self.mempool.values():
                apply_tx(tmp, m)
            if not apply_tx(tmp, t):
                return "reject"
            evicted = False
            if len(self.mempool) >= MAX_MEMPOOL:    # full: replace the lowest-fee tx
                low = min(self.mempool, key=lambda k: self.mempool[k]["fee"])
                if self.mempool[low]["fee"] >= t["fee"]:
                    return "reject"
                del self.mempool[low]
                evicted = True
            self.mempool[i], self.seen[i] = t, time.time()
            if evicted:
                self._refilter()
            return "ok"

    def prune_mempool(self):
        with self.lock:
            old = [k for k, v in self.seen.items() if v < time.time() - MEMPOOL_TTL]
            for k in old:
                self.mempool.pop(k, None)
            if old:
                self._refilter()

    def next_nonce(self, addr):
        with self.lock:
            return self.state.nonce.get(addr, 0) + sum(
                1 for t in self.mempool.values() if t["from"] == addr)

    def _refilter(self):
        tmp, keep = self.state.copy(), {}
        for k, t in self.mempool.items():
            if apply_tx(tmp, t):
                keep[k] = t
        self.mempool = keep
        self.seen = {k: v for k, v in self.seen.items() if k in keep}

    # --- address / transaction index (rebuilt from the chain, so it can't go out of sync)
    def _index_block(self, b):
        h, cb = b["index"], b["txs"][0]
        self.hist.setdefault(cb["to"], []).append((h, None, cb["to"], cb["to"], cb["amount"], 0))
        for t in b["txs"][1:]:
            i = txid(t)
            self.txloc[i] = h
            e = (h, i, t["from"], t["to"], t["amount"], t["fee"])
            self.hist.setdefault(t["from"], []).append(e)
            if t["to"] != t["from"]:
                self.hist.setdefault(t["to"], []).append(e)

    def _reindex(self):
        with self.lock:
            self.hist, self.txloc = {}, {}
            for b in self.blocks[1:]:
                self._index_block(b)

    def history(self, addr, limit):
        with self.lock:
            tip, rows = len(self.blocks) - 1, self.hist.get(addr, [])
            conf = [{"height": h, "confirmations": tip - h + 1, "txid": i,
                     "kind": "reward" if i is None else "tx", "from": "COINBASE" if i is None else f,
                     "to": to, "amount": amt / COIN, "fee": fee / COIN}
                    for h, i, f, to, amt, fee in reversed(rows[-limit:])]
            pend = [{"txid": k, "from": t["from"], "to": t["to"], "amount": t["amount"] / COIN,
                     "fee": t["fee"] / COIN} for k, t in self.mempool.items() if addr in (t["from"], t["to"])]
            return {"address": addr, "tip": tip, "balance": self.state.bal.get(addr, 0) / COIN,
                    "total": len(rows), "confirmed": conf, "pending": pend}

    def tx_status(self, i):
        with self.lock:
            if i in self.mempool:
                return {"txid": i, "status": "pending", "confirmations": 0}
            if i in self.txloc:
                h = self.txloc[i]
                return {"txid": i, "status": "confirmed", "height": h,
                        "confirmations": len(self.blocks) - h}
            return {"txid": i, "status": "unknown"}

    # --- blocks: "ok" | "dup" | "stale" | "orphan" | "bad"
    def add_block(self, b):
        with self.lock:
            if not isinstance(b, dict) or type(b.get("index")) is not int \
                    or not isinstance(b.get("hash"), str):
                return "bad"
            tip = self.blocks[-1]
            if b["hash"] == tip["hash"]:
                return "dup"
            if b.get("prev") == tip["hash"]:
                if not apply_block(self.blocks, self.state, b):
                    return "bad"
                self.blocks.append(b)
                self._index_block(b)
                self.work += 1 << b["bits"]
                self._refilter()
                with open(self.chain_path, "a") as f:
                    f.write(json.dumps(b) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
                return "ok"
            return "orphan" if b["index"] > tip["index"] else "stale"

    # --- sync (incremental, with reorg support)
    def sync_from(self, peer):
        try:
            info = self.rpc(peer, "/info", timeout=6)
            if (info.get("chain") != CHAIN_ID or type(info.get("height")) is not int
                    or type(info.get("work")) is not int):
                return self.ban_peer(peer)
            with self.lock:
                mine, mywork = self.blocks[:], self.work
            if info["work"] <= mywork or not 1 <= info["height"] <= 10 ** 8:
                return
            lo, hi = 0, min(len(mine) - 1, info["height"])      # fork point search
            while lo < hi:
                mid = (lo + hi + 1) // 2
                pb = self.rpc(peer, f"/blocks?start={mid}&count=1")
                if isinstance(pb, list) and pb and isinstance(pb[0], dict) \
                        and pb[0].get("hash") == mine[mid]["hash"]:
                    lo = mid
                else:
                    hi = mid - 1
            fork = lo
            if len(mine) - 1 - fork > self.max_reorg:
                print(f"! refusing reorg deeper than {self.max_reorg} from {peer}")
                return
            new, h = [], fork + 1
            while h <= info["height"] and len(new) <= info["height"]:
                batch = self.rpc(peer, f"/blocks?start={h}&count={BATCH}", timeout=20)
                if not isinstance(batch, list) or not batch:
                    break
                new += batch
                h += len(batch)
            chain = mine[:fork + 1]
            with self.lock:
                at_tip = fork == len(self.blocks) - 1 and self.blocks[fork]["hash"] == chain[fork]["hash"]
                state = self.state.copy() if at_tip else None
            if state is None:
                res = replay(chain)
                if not res:
                    return
                state = res[1]
            for b in new:
                if not apply_block(chain, state, b):
                    return self.ban_peer(peer)
                chain.append(b)
            candwork = sum(1 << b["bits"] for b in chain[1:])
            with self.lock:
                if (candwork > self.work and fork < len(self.blocks)
                        and self.blocks[fork]["hash"] == chain[fork]["hash"]):
                    dropped = self.blocks[fork + 1:]
                    self.blocks, self.state, self.work = chain, state, candwork
                    self._reindex()
                    self._refilter()
                    for b in dropped:                  # orphaned txs -> mempool
                        for t in b["txs"][1:]:
                            self.add_tx(t)
                    self.rewrite()
                    print(f"* synced to height {len(chain) - 1} from {peer}"
                          + (f" (reorg {len(dropped)})" if dropped else ""))
                elif candwork <= mywork:
                    self.ban_peer(peer)                # claimed more work than it delivered
        except Exception:
            return

    def sync_all(self):
        with self.lock:
            if self.syncing:
                return
            self.syncing = True
        try:
            for p in self.live_peers():
                self.sync_from(p)
        finally:
            self.syncing = False

    # --- background loops
    def join(self):
        for u in self.boot:
            self.add_peer(u, trusted=True)
        self.announce_self()
        self.sync_all()

    def maintenance(self):
        t = 0
        while True:
            time.sleep(self.tick)
            t += 1
            try:
                live = self.live_peers()
                for p in random.sample(live, min(3, len(live))):
                    self.sync_from(p)                  # poll: how NAT'd nodes follow
                if t % 6 == 0:
                    self.refresh_peers()
                if t % 12 == 0:
                    self.announce_self()
                    self.save_peers()
                    self.prune_mempool()
            except Exception:
                pass

    def build_template(self, addr):
        """Unsolved block (nonce 0) paying `addr`; the external miner finds the nonce."""
        with self.lock:
            tip, tmp = self.blocks[-1], self.state.copy()
            height = tip["index"] + 1
            bits = expected_bits(self.blocks, height)
            when = max(int(time.time()), median_time(self.blocks) + 1)
            txs, picked, fees = [], set(), 0
            cands = sorted(self.mempool.values(), key=lambda t: (-t["fee"], t["nonce"]))
            for _ in range(4):                         # fee priority, nonce-ordered
                moved = False
                for t in cands:
                    i = txid(t)
                    if i not in picked and len(txs) < MAX_TXS and apply_tx(tmp, t):
                        txs.append(t)
                        picked.add(i)
                        fees += t["fee"]
                        moved = True
                if not moved:
                    break
            cb = {"from": "COINBASE", "to": addr, "amount": reward(height) + fees, "height": height}
            return {"index": height, "prev": tip["hash"], "time": when, "bits": bits,
                    "txs": [cb] + txs, "nonce": 0}


# ------------------------------------------------------------- HTTP server
def status_page(node):
    with node.lock:
        tip, peers = node.blocks[-1], node.live_peers()
        rows = "".join(
            f"<tr><td>{b['index']}</td><td>{b['hash'][:16]}…</td><td>{len(b['txs']) - 1}</td>"
            f"<td>{time.strftime('%H:%M:%S', time.gmtime(b['time']))}</td></tr>"
            for b in reversed(node.blocks[-10:]))
        plist = "".join(f"<li>{html.escape(p)}</li>" for p in peers) or "<li>none</li>"
        return (f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'>"
                f"<title>NyanCoin node</title><body style='font-family:sans-serif;max-width:640px;margin:2em auto'>"
                f"<h2>🐱 NyanCoin node</h2><p>Height <b>{tip['index']}</b> · difficulty {tip['bits']} bits · "
                f"mempool {len(node.mempool)} · peers {len(peers)}<br><small>TLS pin: "
                f"{node.tls_pin or 'none (insecure mode)'}</small></p>"
                f"<h3>Latest blocks</h3><table border=0 cellpadding=4><tr><th>#</th><th>hash</th><th>txs</th>"
                f"<th>time (UTC)</th></tr>{rows}</table><h3>Peers</h3><ul>{plist}</ul>").encode()


def make_handler(node):
    class Handler(BaseHTTPRequestHandler):
        timeout = 10                                  # slow-client protection

        def log_message(self, *a):
            pass

        def reply(self, code, obj, raw=None):
            body = raw if raw is not None else json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html" if raw is not None else "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            ip = ip_key(self.client_address[0])
            if not node.check_ip(ip):
                return self.reply(429, {"error": "slow down"})
            u = urlsplit(self.path)
            q = parse_qs(u.query)
            if u.path == "/":
                return self.reply(200, None, raw=status_page(node))
            with node.lock:
                if u.path == "/info":
                    return self.reply(200, {"height": len(node.blocks) - 1, "work": node.work,
                                            "tip": node.blocks[-1]["hash"], "chain": CHAIN_ID,
                                            "genesis": GENESIS["hash"], "rules": RULES, "version": VERSION, "peers": len(node.peers),
                                            "mempool": len(node.mempool)})
                if u.path == "/blocks":
                    try:
                        start = max(0, int(q.get("start", ["0"])[0]))
                        count = min(BATCH, max(1, int(q.get("count", ["1"])[0])))
                    except ValueError:
                        return self.reply(400, {"error": "bad params"})
                    return self.reply(200, node.blocks[start:start + count])
                if u.path == "/template":
                    a = q.get("addr", [""])[0]
                    if not valid_addr(a):
                        return self.reply(400, {"error": "bad address"})
                    return self.reply(200, node.build_template(a))
                if u.path == "/peers":
                    return self.reply(200, node.peer_list())
                if u.path.startswith("/history/"):
                    a = u.path[9:]
                    if not valid_addr(a):
                        return self.reply(400, {"error": "bad address"})
                    try:
                        limit = min(500, max(1, int(q.get("limit", ["50"])[0])))
                    except ValueError:
                        return self.reply(400, {"error": "bad params"})
                    return self.reply(200, node.history(a, limit))
                if u.path.startswith("/tx/"):
                    i = u.path[4:]
                    if len(i) != 64 or any(c not in "0123456789abcdef" for c in i):
                        return self.reply(400, {"error": "bad txid"})
                    return self.reply(200, node.tx_status(i))
                if u.path.startswith("/balance/"):
                    a = u.path[9:]
                    if not valid_addr(a):
                        return self.reply(400, {"error": "bad address"})
                    return self.reply(200, {"balance": node.state.bal.get(a, 0) / COIN,
                                            "next_nonce": node.next_nonce(a)})
            self.reply(404, {"error": "not found"})

        def do_POST(self):
            ip = ip_key(self.client_address[0])
            if not node.check_ip(ip):
                return self.reply(429, {"error": "slow down"})
            try:
                n = int(self.headers.get("Content-Length", 0))
                if not 0 < n <= MAX_BODY:
                    self.close_connection = True
                    return self.reply(413, {"error": "bad size"})
                obj = json.loads(self.rfile.read(n))
            except Exception:
                node.strike(ip)
                return self.reply(400, {"error": "bad request"})
            if self.path == "/tx":
                r = node.add_tx(obj)
                if r == "ok":
                    node.broadcast("/tx", obj)
                elif r == "bad":
                    node.strike(ip)
                return self.reply(200 if r in ("ok", "dup") else 400,
                                  {"ok": r == "ok", "result": r, "txid": txid(obj) if r == "ok" else None})
            if self.path == "/block":
                r = node.add_block(obj)
                if r == "ok":
                    node.broadcast("/block", obj)
                elif r == "orphan":
                    node._async(node.sync_all)
                elif r == "bad":
                    node.strike(ip, 5)
                return self.reply(200, {"ok": r == "ok", "result": r})
            if self.path == "/peer":
                if isinstance(obj, dict) and valid_peer(obj.get("url")):
                    node._async(node.consider_peer, obj["url"], False, str(obj.get("pin", "")))
                return self.reply(200, {"ok": True})
            self.reply(404, {"error": "not found"})

    return Handler


def main():
    global INSECURE, NET_GUARD
    ap = argparse.ArgumentParser(description="NyanCoin node (no mining, no wallet)")
    ap.add_argument("--version", action="version", version=f"NyanCoin node {VERSION}")
    ap.add_argument("--port", type=int, default=8001)
    ap.add_argument("--host", help="bind address (default: :: dual-stack if --public-url set, else 127.0.0.1)")
    ap.add_argument("--public-url", help="only set if others can reach you (port-forwarded/VPS)")
    ap.add_argument("--peers", nargs="*", default=[], help="bootstrap peers, e.g. https://host:8001#PIN")
    ap.add_argument("--data", help="data directory (default: data-<port>)")
    ap.add_argument("--tick", type=float, default=10, help="seconds between peer polls")
    ap.add_argument("--allow-local-peers", action="store_true", help="allow LAN/loopback peers")
    ap.add_argument("--max-reorg", type=int, default=MAX_REORG)
    ap.add_argument("--insecure", action="store_true", help="plain HTTP instead of TLS (testing only)")
    a = ap.parse_args()

    INSECURE = a.insecure
    NET_GUARD = not a.allow_local_peers
    data = a.data or f"data-{a.port}"
    os.makedirs(data, exist_ok=True)
    public = a.public_url.partition("#")[0] if a.public_url else None
    if public and not valid_peer(public):
        sys.exit("--public-url must be https:// (or http:// with --insecure)")
    host = a.host or ("::" if public else "127.0.0.1")     # public: IPv6+IPv4 dual-stack
    node = Node(data, a.peers, public, a.allow_local_peers, a.tick, a.max_reorg)
    try:
        srv = make_server(host, a.port, make_handler(node))
    except OSError:
        if a.host:                                      # explicit --host: don't second-guess
            raise
        host = "0.0.0.0"                                # no IPv6 on this machine: IPv4 only
        print("! IPv6 not available on this machine, listening on IPv4 only")
        srv = make_server(host, a.port, make_handler(node))
    if INSECURE:
        node.tls_pin, mode = None, "PLAIN HTTP (insecure!)"
    else:
        kp, cp, node.tls_pin = ensure_cert(data, urlsplit(public).hostname if public else None)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cp, kp)
        srv.ctx, mode = ctx, "TLS"
    threading.Thread(target=node.join, daemon=True).start()
    threading.Thread(target=node.maintenance, daemon=True).start()
    stack = "IPv4+IPv6" if host == "::" else ("IPv6" if ":" in host else "IPv4")
    print(f"NyanCoin node {VERSION} on {hostkey(host, a.port)} ({stack}) [{mode}] height={len(node.blocks) - 1} "
          f"inbound={'yes' if public else 'no (outbound-only, polling)'}")
    if node.tls_pin:
        print(f"TLS pin: {node.tls_pin}")
        if public:
            print(f"Share this seed address: {public}#{node.tls_pin}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
