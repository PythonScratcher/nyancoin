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
# ======================================================================
# GUI wallet code
# ======================================================================
import queue as _queue
import random as _random
import time as _time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

GUI_VERSION = "1.0.0"
DEFAULT_NODE = "https://127.0.0.1:8001"
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
