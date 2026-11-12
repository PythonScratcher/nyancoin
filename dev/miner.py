#!/usr/bin/env python3
"""NyanCoin miner: asks a node for an unsolved block, hashes it on all CPU cores,
and submits the solution back to the node.  Runs separately from the node (even on
another machine).  It never trusts the node blindly: the block template must pay
YOUR address, with the correct reward, valid transactions and sane difficulty.

  python3 miner.py --address NYAN... --node https://127.0.0.1:8001 [--procs N]
  (remote node: --node "https://host:8001#PIN" to verify its TLS identity)
"""
import argparse, hashlib, os, sys, time

from nyancore import *          # shared rules + pinned-TLS client

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
    while True:
        try:
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
    ap.add_argument("--node", default="https://inter.net.sh:8001#aacf9733d8a238bc0f8a62232e5ab5b804cd3fe80b32e90c58bd70ff52f1fc41",
                    help="node to mine through (default: the official seed)")
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
