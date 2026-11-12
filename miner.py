#!/usr/bin/env python3
"""NyanCoin miner: asks a node for an unsolved block, hashes it on all CPU cores,
and submits the solution back to the node.  Runs separately from the node (even on
another machine).  It never trusts the node blindly: the block template must pay
YOUR address, with the correct reward, valid transactions and sane difficulty.

  python3 miner.py --address NYAN... --node https://127.0.0.1:8001 [--procs N]
  (remote node: --node "https://host:8001#PIN" to verify its TLS identity)

Self-contained: this single file is all you need (plus: pip install cryptography).
Consensus rules are locked: the file refuses to start if its shared-rules section is edited.
"""
import argparse, hashlib, http.client, ipaddress, json, os, socket, ssl, sys, threading, time
import urllib.error, urllib.request
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

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


def header_prefix(b):
    return canon({k: b[k] for k in ("index", "prev", "time", "bits", "txs")}) + "|"


def block_hash(b):
    return H(header_prefix(b) + str(b["nonce"]))


def reward(height):
    return REWARD0 >> (height // HALVING)



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
EXPECTED_SHARED_HASH = "59afc1fd5026d3adb19cd1d75460fa7dc4a9030171f7975542fc99f678df934b"


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
# miner code
# ======================================================================
VERSION = "1.0.0"

def _worker(prefix, bits, start, step, stop, out, counter):
    base, target, n, c = hashlib.sha256(prefix.encode()), 1 << (256 - bits), start, 0
    while True:
        h = base.copy()
        h.update(str(n).encode())
        if int.from_bytes(h.digest(), "big") < target:
            out.put(n)
            return
        n += step
        c += 1
        if c == 20000:
            c = 0
            with counter.get_lock():
                counter.value += 20000
            if stop.is_set():
                return


def verify_template(b, addr):
    """Don't blindly trust the node: make sure the block pays US and is well-formed."""
    try:
        if not isinstance(b, dict) or set(b) != {"index", "prev", "time", "bits", "txs", "nonce"}:
            return False
        if (b["nonce"] != 0 or any(type(b[k]) is not int for k in ("index", "time", "bits"))
                or b["index"] < 1 or not MIN_BITS <= b["bits"] <= MAX_BITS
                or abs(b["time"] - time.time()) > MAX_FUTURE
                or not isinstance(b["prev"], str) or len(b["prev"]) != 64):
            return False
        cb, rest = b["txs"][0], b["txs"][1:]
        return (len(b["txs"]) <= MAX_TXS + 1 and all(check_tx(t) for t in rest)
                and cb == {"from": "COINBASE", "to": addr, "height": b["index"],
                           "amount": reward(b["index"]) + sum(t["fee"] for t in rest)})
    except Exception:
        return False


def run_miner(node_url, addr, procs):
    """Standalone miner: fetch template from a node, hash on all cores, submit."""
    import multiprocessing as mp, queue
    print(f"miner -> {node_url}, paying {addr}, {procs} process(es)")
    checked = False
    while True:
        try:
            if not checked:
                check_rules(node_url)
                checked = True
            b = http(node_url, f"/template?addr={addr}", timeout=10)
            if not verify_template(b, addr):
                print("! node sent a bad/dishonest block template; refusing to mine it")
                time.sleep(5)
                continue
            prefix = header_prefix(b)
        except Exception as e:
            print("node unreachable, retrying…", type(e).__name__)
            time.sleep(3)
            continue
        stop, out, counter = mp.Event(), mp.Queue(), mp.Value("Q", 0)
        ps = [mp.Process(target=_worker, args=(prefix, b["bits"], i, procs, stop, out, counter),
                         daemon=True) for i in range(procs)]
        for p in ps:
            p.start()
        t0, last_poll, nonce = time.time(), time.time(), None
        while nonce is None:
            try:
                nonce = out.get(timeout=1)
            except queue.Empty:
                if time.time() - last_poll >= 2:        # stale-tip check
                    last_poll = time.time()
                    try:
                        if http(node_url, "/info", timeout=5)["tip"] != b["prev"]:
                            break
                    except Exception:
                        pass
                if time.time() - t0 > 30:               # refresh: new txs + timestamp
                    break
        stop.set()
        for p in ps:
            p.terminate()
        if nonce is None:
            continue
        b["nonce"] = nonce
        b["hash"] = block_hash(b)
        rate = counter.value / max(time.time() - t0, 0.001) / 1000
        try:
            r = http(node_url, "/block", b, timeout=10)
            print(f"{'+' if r.get('ok') else '-'} block {b['index']} {b['hash'][:12]} "
                  f"({len(b['txs']) - 1} txs, ~{rate:.0f} kH/s) -> {r.get('result')}")
        except Exception as e:
            print("submit failed:", type(e).__name__)


def main():
    ap = argparse.ArgumentParser(description="NyanCoin miner")
    ap.add_argument("--version", action="version", version=f"NyanCoin miner {VERSION}")
    ap.add_argument("--address", required=True, help="address that receives block rewards")
    ap.add_argument("--node", default="https://127.0.0.1:8001")
    ap.add_argument("--procs", type=int, default=os.cpu_count() or 1)
    a = ap.parse_args()
    if not valid_addr(a.address):
        sys.exit("invalid --address")
    try:
        run_miner(a.node, a.address, max(1, a.procs))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
