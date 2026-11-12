import re, hashlib, os
os.chdir(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.dirname(os.getcwd())
def H(x):
    return hashlib.sha256(x.encode()).hexdigest()
core = open("nyancore.py").read()
chunks = core.split("\n\n\n")
consts = chunks[0][chunks[0].index("# ---------------------------------------------------------------- consensus"):]
consts = re.sub(r"CHECKPOINTS = \{\}.*\n\s+# \(generate.*\n", "", consts)
assert "CHECKPOINTS" not in consts
_start = next(i for i, c in enumerate(chunks) if "PIN_LOCK = threading.Lock()" in c)
tls = "\n\n\n".join(chunks[_start:])   # whole TLS client section, by name
assert "def http(" in tls

def chunk(*idx):
    return "\n\n\n".join(chunks[i] for i in idx)

RULES = '''RULES = H(canon([CHAIN_ID, COIN, REWARD0, HALVING, INIT_BITS, MIN_BITS, MAX_BITS, RETARGET,
                 TARGET_SPACING, MAX_TXS, MAX_FUTURE, MAX_INT, MAX_BLOCK_BYTES]))
# ^ fingerprint of the shared consensus constants; wallet/miner refuse nodes that differ'''

CHECK_RULES = '''def check_rules(node_url):
    """Refuse to talk to a node running different consensus rules (version mismatch)."""
    if http(node_url, "/info").get("rules") != RULES:
        sys.exit("version mismatch: this program and the node use different NyanCoin rules - update both")'''

CORE_IMPORTS = '''import hashlib, http.client, ipaddress, json, os, socket, ssl, sys, threading, time
import urllib.error, urllib.request
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
'''
BANNER = "\n# ======================================================================\n# SHARED RULES - identical in node.py / miner.py / wallet.py (keep in sync;\n# programs refuse to talk to a node whose RULES fingerprint differs)\n# ======================================================================\n"
ROLE = "\n# ======================================================================\n# {}\n# ======================================================================\n"

def split_role(path):
    t = open(path).read()
    m = re.search(r"^from nyancore import \*.*\n", t, re.M)
    header, body = t[:m.start()], t[m.end():]
    header = header.replace("import nyancore\n", "")
    return header, body

def selfcontained(header):
    return header.replace('\n"""\n', '\n\nSelf-contained: this single file is all you need (plus: pip install cryptography).\nConsensus rules are locked: the file refuses to start if its shared-rules section is edited.\n"""\n', 1)

IMPORTS = {
 "node": """import argparse, datetime, hashlib, html, http.client, ipaddress, json, os, random, socket, ssl
import sys, threading, time, urllib.error, urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509.oid import NameOID
""",
 "miner": """import argparse, hashlib, http.client, ipaddress, json, os, socket, ssl, sys, threading, time
import urllib.error, urllib.request
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
""",
 "wallet": """import argparse, getpass, hashlib, hmac, http.client, ipaddress, json, os, random, socket, ssl
import sys, threading, unicodedata
import urllib.error, urllib.request
from decimal import Decimal, InvalidOperation
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
""",
}

BEGIN = "# >>> SHARED RULES BEGIN"
END = "# <<< SHARED RULES END"

LOCK = '''# ---- rules lock: refuse to run if the shared rules above were modified ----------------
EXPECTED_SHARED_HASH = "{hash}"


def _verify_rules_lock():
    try:
        with open(__file__, encoding="utf-8") as f:
            src = f.read().replace("\\r\\n", "\\n")
    except (OSError, NameError):
        return
    region = src[src.index("# >>> SHARED RULES" + " BEGIN"):src.index("# <<< SHARED RULES" + " END")]
    if H(region) != EXPECTED_SHARED_HASH:
        sys.exit("The shared consensus rules in this file were modified. Running modified rules "
                 "would split you from the NyanCoin network, so this program refuses to start. "
                 "Re-download the original file.")


_verify_rules_lock()'''


def build(role, header, body, parts):
    doc = selfcontained(header)
    doc = doc[:doc.index('\n"""\n') + 5]
    shared = (BEGIN + " (locked: editing anything between BEGIN and END stops the program from starting)\n"
              + BANNER.strip("\n") + "\n" + consts.rstrip() + "\n\n\n" + parts.rstrip() + "\n" + END + "\n")
    digest = H(shared[shared.index(BEGIN):shared.index(END)])
    out = (doc + IMPORTS[role] + "\n" + shared + "\n" + LOCK.format(hash=digest) + "\n"
           + ROLE.format(role + " code") + body.lstrip("\n"))
    open(f"{OUT}/{role}.py", "w").write(out.rstrip() + "\n")

# ---- node: everything
h, b = split_role("node.py")
b = b.replace("    global INSECURE\n", "    global INSECURE, NET_GUARD\n").replace("    nyancore.NET_GUARD = not a.allow_local_peers", "    NET_GUARD = not a.allow_local_peers")
assert b.count('"genesis": GENESIS["hash"], ') == 1
b = b.replace('"genesis": GENESIS["hash"], ', '"genesis": GENESIS["hash"], "rules": RULES, ')
b = b.replace('if info.get("chain") == CHAIN_ID and info.get("genesis") == GENESIS["hash"]:',
              'if (info.get("chain") == CHAIN_ID and info.get("genesis") == GENESIS["hash"]\n                and info.get("rules") == RULES):')
b = ("# ---- editable: official checkpoints (height -> block hash). Get a line with\n"
     "#      python3 wallet.py checkpoint --node URL   and add it here ONLY if the network agrees.\n"
     "#      Blocks that contradict a checkpoint are rejected; history before it can never be rewritten.\n"
     "CHECKPOINTS = {}\n\n") + b
assert "RULES" in b and "NET_GUARD = not" in b
build("node", h, b, chunk(1, 2) + "\n\n\n" + RULES + "\n\n\n" + chunk(3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21) + "\n\n\n" + tls)

# ---- miner
h, b = split_role("miner.py")
b = b.replace('    print(f"miner -> {node_url}, paying {addr}, {procs} process(es)")\n    while True:',
              '    print(f"miner -> {node_url}, paying {addr}, {procs} process(es)")\n    checked = False\n    while True:')
b = b.replace('            b = http(node_url, f"/template?addr={addr}", timeout=10)',
              '            if not checked:\n                check_rules(node_url)\n                checked = True\n            b = http(node_url, f"/template?addr={addr}", timeout=10)')
assert "check_rules" in b
build("miner", h, b, chunk(1, 2) + "\n\n\n" + RULES + "\n\n\n" + chunk(3, 4, 5, 6, 8, 12, 13, 15) + "\n\n\n" + tls + "\n\n\n" + CHECK_RULES + "\n")

# ---- wallet
h, b = split_role("wallet.py")
b = b.replace('    nonce = http(args.node, f"/balance/{w[\'address\']}")["next_nonce"]',
              '    check_rules(args.node)\n    nonce = http(args.node, f"/balance/{w[\'address\']}")["next_nonce"]')
h = h.replace("for nyancore.py", "for node.py")
assert "check_rules(args.node)" in b
build("wallet", h, b, chunk(1, 2) + "\n\n\n" + RULES + "\n\n\n" + chunk(3, 4, 6) + "\n\n\n" + tls + "\n\n\n" + CHECK_RULES + "\n")


# ---- GUI programs = a generated CLI file (same locked rules + code) + GUI code on top
def build_gui(cli, gui_src, out):
    wsrc = open(f"{OUT}/{cli}").read()
    gui = open(gui_src).read()
    end = '\n"""\n'
    gdoc, gbody = gui[:gui.index(end) + len(end)], gui[gui.index(end) + len(end):]
    body = wsrc[wsrc.index(end) + len(end):]
    assert body.count("\ndef main():") == 1 and body.count('if __name__ == "__main__":') == 1
    body = body.replace("\ndef main():", "\ndef cli_main():", 1)
    body = body[:body.rindex('if __name__ == "__main__":')].rstrip()
    open(f"{OUT}/{out}", "w").write(gdoc + body + "\n\n\n" + gbody)


build_gui("wallet.py", "gui.py", "gui_wallet.py")
build_gui("miner.py", "gui_miner_src.py", "gui_miner.py")
