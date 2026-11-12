#!/usr/bin/env python3
"""NyanCoin GUI miner: the same miner as miner.py, with a window.

  python3 gui_miner.py

Enter (or load from a wallet file) the address that should receive rewards, pick a node and how
many CPU cores to use, and press Start. Shows hashrate, the block being worked on, blocks found,
your balance, and a log. Like miner.py it never trusts the node blindly: every block template must
pay YOUR address with the correct reward, or it is refused.

Needs: Python 3 with Tkinter (Windows/macOS: included; Debian/Ubuntu: sudo apt install python3-tk)
and  pip install cryptography.  Self-contained: miner.py is not needed next to it.
No wallet password is needed: mining only needs your address, never your keys.
"""
# ======================================================================
# GUI miner code
# ======================================================================
import multiprocessing as _mp
import queue as _queue
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

GUI_VERSION = "1.0.0"
DEFAULT_NODE = "https://inter.net.sh:8001#aacf9733d8a238bc0f8a62232e5ab5b804cd3fe80b32e90c58bd70ff52f1fc41"   # official seed
CONFIG = os.path.join(HOME, "gui_miner.json")


class Exit(Exception):
    """A miner function wanted to stop with a message (sys.exit) - show it instead."""


def call(fn, *a):
    try:
        return fn(*a)
    except SystemExit as e:
        raise Exit(str(e.code) if e.code not in (None, 0) else "stopped")


def fmt_rate(h):
    for unit, div in (("MH/s", 1e6), ("kH/s", 1e3)):
        if h >= div:
            return f"{h / div:,.2f} {unit}"
    return f"{h:,.0f} H/s"


def fmt_secs(s):
    if s < 120:
        return f"{s:,.0f} s"
    if s < 7200:
        return f"{s / 60:,.0f} min"
    if s < 172800:
        return f"{s / 3600:,.1f} h"
    return f"{s / 86400:,.1f} days"


def short_err(e):
    if isinstance(e, Exit):
        return str(e)
    if isinstance(e, urllib.error.HTTPError):
        return f"node answered HTTP {e.code}"
    if isinstance(e, urllib.error.URLError):
        return f"can't reach node ({e.reason})"
    return f"{type(e).__name__}: {e}"


class Engine:
    """Mining loop in a background thread; hashing in worker processes (one per core).
    Talks to the window only through `events` (thread-safe queue)."""

    def __init__(self, events):
        self.events = events
        self.halt = threading.Event()
        self.thread = None

    def emit(self, kind, **kw):
        self.events.put((kind, kw))

    @property
    def running(self):
        return self.thread is not None and self.thread.is_alive()

    def start(self, node, addr, procs):
        self.halt.clear()
        self.thread = threading.Thread(target=self._loop, args=(node, addr, procs), daemon=True)
        self.thread.start()

    def stop(self):
        self.halt.set()

    def _loop(self, node, addr, procs):
        self.emit("state", running=True)
        try:
            self._mine(node, addr, procs)
        except Exit as e:
            self.emit("fatal", msg=str(e))
        except Exception as e:                      # never die silently
            self.emit("fatal", msg=short_err(e))
        finally:
            self.emit("state", running=False)

    def _mine(self, node, addr, procs):
        call(check_rules, node)
        self.emit("log", msg=f"Connected to {node.split('#')[0]}; mining with {procs} core(s).")
        while not self.halt.is_set():
            try:
                b = http(node, f"/template?addr={addr}", timeout=10)
            except Exception as e:
                self.emit("status", msg=f"Waiting for node: {short_err(e)}")
                self.halt.wait(3)
                continue
            if not verify_template(b, addr):
                self.emit("log", msg="! Node sent a bad/dishonest block template - refusing to mine it.")
                self.halt.wait(5)
                continue
            self.emit("job", height=b["index"], bits=b["bits"], txs=len(b["txs"]) - 1)
            stop, out, counter = _mp.Event(), _mp.Queue(), _mp.Value("Q", 0)
            ps = [_mp.Process(target=_worker, args=(header_prefix(b), b["bits"], i, procs, stop, out, counter),
                              daemon=True) for i in range(procs)]
            for p in ps:
                p.start()
            t0 = last_poll = time.time()
            nonce = None
            try:
                while nonce is None and not self.halt.is_set():
                    try:
                        nonce = out.get(timeout=1)
                    except _queue.Empty:
                        el = time.time() - t0
                        self.emit("rate", rate=counter.value / max(el, 0.001))
                        if time.time() - last_poll >= 2:           # someone else found the block?
                            last_poll = time.time()
                            try:
                                if http(node, "/info", timeout=5)["tip"] != b["prev"]:
                                    break
                            except Exception:
                                pass
                        if el > 30:                                 # refresh: new txs + timestamp
                            break
            finally:
                stop.set()
                for p in ps:
                    p.terminate()
                for p in ps:
                    p.join(timeout=2)
            if nonce is None:
                continue
            b["nonce"] = nonce
            b["hash"] = block_hash(b)
            try:
                r = http(node, "/block", b, timeout=10)
                self.emit("found", height=b["index"], hash=b["hash"], ok=bool(r.get("ok")),
                          result=r.get("result"), reward=b["txs"][0]["amount"] / COIN)
            except Exception as e:
                self.emit("log", msg=f"Found block {b['index']} but couldn't submit it: {short_err(e)}")


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
        root.title("NyanCoin Miner")
        root.geometry("760x600")
        root.minsize(640, 520)
        st = ttk.Style()
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure("Title.TLabel", font=("TkDefaultFont", 18, "bold"))
        st.configure("Big.TLabel", font=("TkDefaultFont", 20, "bold"))
        st.configure("Muted.TLabel", foreground="#666666")
        st.configure("Ok.TLabel", foreground="#0a7d32")
        st.configure("Warn.TLabel", foreground="#b00020")
        cfg = _load_cfg()
        cores = os.cpu_count() or 1
        self.addr = tk.StringVar(value=cfg.get("address", ""))
        self.node = tk.StringVar(value=cfg.get("node", DEFAULT_NODE))
        self.procs = tk.IntVar(value=min(max(1, int(cfg.get("procs", max(1, cores - 1)))), cores))
        self.events = _queue.Queue()
        self.engine = Engine(self.events)
        self.found = self.rejected = 0
        self.bits = None
        self.rate = 0.0
        self.build(cores)
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(200, self.pump)
        root.after(1000, self.refresh_balance)

    # ------------------------------------------------------------------ layout
    def build(self, cores):
        f = ttk.Frame(self.root, padding=18)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="NyanCoin Miner", style="Title.TLabel").grid(row=0, column=0, columnspan=3, sticky="w")
        ttk.Label(f, text="Mining only needs your address. Your wallet password and keys are never used.",
                  style="Muted.TLabel").grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 12))

        ttk.Label(f, text="Reward address").grid(row=2, column=0, sticky="w")
        self.addr_entry = ttk.Entry(f, textvariable=self.addr, width=52, font=("TkFixedFont", 11))
        self.addr_entry.grid(row=2, column=1, sticky="we", padx=8, pady=3)
        self.load_btn = ttk.Button(f, text="From wallet file…", command=self.load_wallet)
        self.load_btn.grid(row=2, column=2, sticky="w")
        ttk.Label(f, text="Node").grid(row=3, column=0, sticky="w")
        self.node_entry = ttk.Entry(f, textvariable=self.node, width=52)
        self.node_entry.grid(row=3, column=1, sticky="we", padx=8, pady=3)
        ttk.Label(f, text="CPU cores").grid(row=4, column=0, sticky="w")
        cf = ttk.Frame(f)
        cf.grid(row=4, column=1, sticky="w", padx=8, pady=3)
        self.core_scale = ttk.Scale(cf, from_=1, to=cores, orient="horizontal", length=220,
                                    command=lambda v: self.procs.set(int(round(float(v)))))
        self.core_scale.set(self.procs.get())
        self.core_scale.pack(side="left")
        self.core_lbl = ttk.Label(cf, text="", width=22)
        self.core_lbl.pack(side="left", padx=8)
        self.procs.trace_add("write", lambda *_: self.core_lbl.configure(
            text=f"{self.procs.get()} of {cores}" + ("  (leaves 1 free)" if self.procs.get() == cores - 1 else "")))
        self.procs.set(self.procs.get())
        f.columnconfigure(1, weight=1)

        self.btn = ttk.Button(f, text="Start mining", command=self.toggle)
        self.btn.grid(row=5, column=1, sticky="w", padx=8, pady=(12, 6), ipadx=10, ipady=4)

        stats = ttk.Frame(f, padding=(0, 8))
        stats.grid(row=6, column=0, columnspan=3, sticky="we")
        self.v = {}
        for i, (key, label) in enumerate((("status", "Status"), ("rate", "Hashrate"), ("job", "Working on"),
                                          ("eta", "Your expected time per block"), ("found", "Blocks found"),
                                          ("balance", "Address balance"))):
            ttk.Label(stats, text=label, style="Muted.TLabel").grid(row=i // 2 * 2, column=i % 2, sticky="w", padx=(0, 40))
            lbl = ttk.Label(stats, text="—", style="Big.TLabel" if key in ("rate", "balance") else "TLabel")
            lbl.grid(row=i // 2 * 2 + 1, column=i % 2, sticky="w", padx=(0, 40), pady=(0, 8))
            self.v[key] = lbl
        self.v["status"].configure(text="Stopped")

        ttk.Label(f, text="Log", style="Muted.TLabel").grid(row=7, column=0, sticky="w")
        lf = ttk.Frame(f)
        lf.grid(row=8, column=0, columnspan=3, sticky="nsew")
        f.rowconfigure(8, weight=1)
        self.logbox = tk.Text(lf, height=8, wrap="word", font=("TkFixedFont", 10), state="disabled")
        sb = ttk.Scrollbar(lf, orient="vertical", command=self.logbox.yview)
        self.logbox.configure(yscrollcommand=sb.set)
        self.logbox.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")
        self.logbox.tag_configure("ok", foreground="#0a7d32")
        self.logbox.tag_configure("bad", foreground="#b00020")

    # ----------------------------------------------------------------- actions
    def log(self, msg, tag=None):
        self.logbox.configure(state="normal")
        self.logbox.insert("end", time.strftime("%H:%M:%S  ") + msg + "\n", tag or ())
        if int(self.logbox.index("end-1c").split(".")[0]) > 500:
            self.logbox.delete("1.0", "100.0")
        self.logbox.see("end")
        self.logbox.configure(state="disabled")

    def load_wallet(self):
        p = filedialog.askopenfilename(parent=self.root, title="Choose wallet file (only its address is read)",
                                       filetypes=[("Wallet", "*.json"), ("All files", "*")])
        if not p:
            return
        try:
            with open(p) as fh:
                a = json.load(fh)["address"]
            if not valid_addr(a):
                raise ValueError
        except Exception:
            return messagebox.showerror("Miner", "That isn't a NyanCoin wallet file.", parent=self.root)
        self.addr.set(a)

    def save_cfg(self):
        try:
            os.makedirs(HOME, exist_ok=True)
            with open(CONFIG, "w") as fh:
                json.dump({"address": self.addr.get().strip(), "node": self.node.get().strip(),
                           "procs": self.procs.get()}, fh)
        except OSError:
            pass

    def set_inputs(self, enabled):
        s = "normal" if enabled else "disabled"
        for w in (self.addr_entry, self.node_entry, self.load_btn, self.core_scale):
            w.configure(state=s)

    def toggle(self):
        if self.engine.running:
            self.engine.stop()
            self.btn.configure(text="Stopping…", state="disabled")
            self.v["status"].configure(text="Stopping…")
            return
        addr, node = self.addr.get().strip(), self.node.get().strip() or DEFAULT_NODE
        if not valid_addr(addr):
            return messagebox.showerror("Miner", "Enter a valid reward address (starts with NYAN), or load it "
                                        "from your wallet file.", parent=self.root)
        self.save_cfg()
        self.set_inputs(False)
        self.btn.configure(text="Stop mining")
        self.v["status"].configure(text="Connecting…", style="TLabel")
        self.engine.start(node, addr, self.procs.get())

    def pump(self):
        """Apply engine events to the window (runs on the Tk thread)."""
        try:
            while True:
                kind, kw = self.events.get_nowait()
                if kind == "state":
                    if kw["running"]:
                        self.v["status"].configure(text="Mining", style="Ok.TLabel")
                    else:
                        self.set_inputs(True)
                        self.btn.configure(text="Start mining", state="normal")
                        if self.v["status"].cget("text") != "Error":
                            self.v["status"].configure(text="Stopped", style="TLabel")
                        self.v["rate"].configure(text="—")
                        self.log("Stopped.")
                elif kind == "fatal":
                    self.v["status"].configure(text="Error", style="Warn.TLabel")
                    self.log(kw["msg"], "bad")
                    messagebox.showerror("Miner", kw["msg"], parent=self.root)
                elif kind == "balance":
                    self.v["balance"].configure(text=f"{kw['value']:,.8f} NYAN")
                elif kind == "status":
                    self.v["status"].configure(text=kw["msg"][:60], style="Warn.TLabel")
                elif kind == "log":
                    self.log(kw["msg"], "bad" if kw["msg"].startswith("!") else None)
                elif kind == "job":
                    self.bits = kw["bits"]
                    self.v["status"].configure(text="Mining", style="Ok.TLabel")
                    self.v["job"].configure(text=f"block {kw['height']}  ·  {kw['txs']} payment(s)  ·  "
                                                 f"difficulty {kw['bits']} bits")
                    self.update_eta()
                elif kind == "rate":
                    self.rate = kw["rate"]
                    self.v["rate"].configure(text=fmt_rate(self.rate))
                    self.update_eta()
                elif kind == "found":
                    if kw["ok"]:
                        self.found += 1
                        self.log(f"Found block {kw['height']}! +{kw['reward']:.8f} NYAN  ({kw['hash'][:16]}…)", "ok")
                    else:
                        self.rejected += 1
                        self.log(f"Block {kw['height']} not accepted ({kw['result']}) - usually someone else "
                                 "found it first.", "bad")
                    self.v["found"].configure(text=f"{self.found} accepted" +
                                              (f", {self.rejected} too late" if self.rejected else ""))
                    self.refresh_balance(once=True)
        except _queue.Empty:
            pass
        self.root.after(200, self.pump)

    def update_eta(self):
        if self.bits and self.rate > 0:
            self.v["eta"].configure(text="about " + fmt_secs((1 << self.bits) / self.rate))

    def refresh_balance(self, once=False):
        addr, node = self.addr.get().strip(), self.node.get().strip() or DEFAULT_NODE
        if valid_addr(addr):
            def work():
                try:
                    r = http(node, f"/balance/{addr}", timeout=6)
                    self.events.put(("balance", {"value": r["balance"]}))
                except Exception:
                    pass
            threading.Thread(target=work, daemon=True).start()
        if not once:
            self.root.after(15000, self.refresh_balance)

    def on_close(self):
        if self.engine.running:
            self.engine.stop()
            self.engine.thread.join(timeout=5)        # lets workers be terminated cleanly
        self.save_cfg()
        self.root.destroy()


def main():
    if any(a in ("-h", "--help") for a in sys.argv[1:]):
        print(__doc__)
        return
    if "--version" in sys.argv[1:]:
        print(f"NyanCoin GUI miner {GUI_VERSION}")
        return
    _mp.freeze_support()
    try:
        root = tk.Tk()
    except tk.TclError as e:
        sys.exit(f"Can't open a window ({e}). On servers use miner.py instead.")
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
