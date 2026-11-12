# NyanCoin 🐱✨

hi!! this is **NyanCoin**, a little peer-to-peer proof-of-work crypto i made for fun =^･ω･^=

it's got nodes that talk to each other, wallets with recovery phrases, miners for your PC, your phone, and even an **ESP8266 with an e-ink screen**. everything is encrypted and checked, so nobody can just make up coins.

> ⚠️ **heads up:** this is a hobby project. it's built carefully and tested a bunch, but nobody has audited it and
> the network is tiny. don't put real money you care about into it lol

<p>
<img src="android/screenshots/2_wallet.png" width="200"> <img src="android/screenshots/3_mine.png" width="200">
<img src="android/screenshots/4_settings.png" width="200">
</p>

## what's in the box 📦

| thing | who it's for | what it does |
|---|---|---|
| `node.py` | server people | keeps the blockchain, checks everything, talks to other nodes. doesn't mine, doesn't hold keys |
| `wallet.py` | everyone | make a wallet, check your balance, send coins |
| `miner.py` | miners | mines on all your CPU cores. that's it, that's the whole job |
| `gui_wallet.py` | people who like windows | the wallet but with buttons |
| `gui_miner.py` | people who like windows | the miner but with buttons and a hashrate counter |
| `android/` | phone people | a real native Android app: wallet + miner, dark mode 🌙 |
| `esp8266/` | tinkerers | Arduino miner for an ESP8266 + Waveshare 2.13" e-ink V4 screen. see `esp8266/README.md` |

each Python file works **on its own**, so you can send a friend just `wallet.py` and that's all they need.

you need Python 3 (made on 3.13) and `pip install cryptography`. nothing else!

## quick start 🚀

the wallet and miner connect to the main seed node, **`inter.net.sh`**, out of the box. its key is pinned in the code, so you can't get tricked by a fake one. you don't need your own node to play!

```bash
pip install cryptography

# 1. make a wallet (it shows your 24 words, then asks for a password, 12+ characters)
python3 wallet.py new wallet.json
python3 wallet.py show wallet.json            # your address: NYAN...

# 2. mine! rewards go to your address
python3 miner.py --address NYAN...youraddress

# 3. look at your coins and spend them
python3 wallet.py history wallet.json
python3 wallet.py send --wallet wallet.json --to NYAN...friend --amount 1.5
python3 wallet.py status
```

prefer clicking? `python3 gui_wallet.py` and `python3 gui_miner.py` 🖱️

## 📱 the android app

a proper native app (Kotlin + Jetpack Compose), **not** a website in a box. it signs payments, mines and checks node keys all by itself.

- make a new wallet or restore one from your words (typing just the first 4 letters of each word works)
- balance, history, send (asks for your password), receive with a QR code
- mine on your phone's CPU, with a threads slider and a keep-screen-on toggle
- the wallet file is the same format as `wallet.py`, so the PC and phone wallets can open each other's files

**download:** [NyanCoin-1.0.0.apk](https://glide.pythonscratcher.net/files/afjiQP-NyanCoin-1.0.0.apk) (when Android asks, allow "install unknown apps")

build it yourself (JDK 17 + Android SDK):

```bash
cd android
gradle assembleRelease      # -> app/build/outputs/apk/release/app-release.apk
gradle testDebugUnitTest    # checks the Kotlin code against Python-made test vectors
```

phone mining is mostly for fun. phones are way slower than PCs, and Android slows apps down once the screen is off 😴

## the numbers 🔢

| | |
|---|---|
| block reward | 1 NYAN, halves every 10,500,000 blocks (about every 3.3 years) |
| max supply | just under 21,000,000 NYAN. no premine, the genesis block is empty |
| block time | aims for 10 seconds, difficulty adjusts every 10 blocks |
| smallest bit | 0.00000001 NYAN |
| addresses | `NYAN` + 44 characters, with a checksum so typos get caught |
| fees | go to whoever mines the block. minimum to get relayed: 0.00001 NYAN |
| signatures | Ed25519 |
| network id | `nyancoin-2` |

**what's the fee for??** when you send coins, the fee is a tip for the miner who puts your payment in a block. if blocks get full, miners pick the biggest tips first. the default 0.0001 is plenty right now.

## all the wallet.py commands 📜

| command | what it does |
|---|---|
| `new FILE [--words 12\|24]` | new wallet + recovery phrase |
| `seed FILE` | show your recovery phrase again (needs password) |
| `restore FILE` | rebuild a wallet from your words |
| `show FILE` | print your address (no password needed) |
| `balance ADDRESS` | balance + next nonce |
| `history ADDRESS_OR_FILE [--limit N]` | payments in/out, rewards, pending stuff, confirmations |
| `tx TXID` | is that payment pending, confirmed, or unknown? |
| `send --wallet FILE --to ADDRESS --amount N [--fee F]` | send coins (default fee 0.0001) |
| `status` | what the node is up to |
| `checkpoint [--height H]` | print a `CHECKPOINTS` line (see below) |

all of them take `--node URL` if you want a different node.

**node.py** options: `--port`, `--public-url`, `--peers`, `--host`, `--data`, `--tick`, `--allow-local-peers`, `--max-reorg`, `--insecure` (plain HTTP, testing only!).
**miner.py** options: `--address` (needed), `--node`, `--procs`.

## running your own node 🖥️

it's good for the network and better for your privacy:

```bash
python3 node.py --port 8001
```

it finds the seed by itself. then add `--node https://127.0.0.1:8001` to your wallet/miner commands, or set it in the GUI settings. there's a little status page at `https://127.0.0.1:8001/` too (your browser will moan about the certificate, that's normal).

### making a public seed node

on a VPS, open the port in the firewall, then:

```bash
python3 node.py --port 8001 --public-url https://YOUR.IP.OR.DOMAIN:8001
```

it prints something like:

```
TLS pin: 3f9a...
Share this seed address: https://YOUR.IP:8001#3f9a...
```

that `#3f9a...` bit is the **pin**: a fingerprint of your node's key. anyone who uses the address with the pin knows for sure they're talking to *your* node and not an imposter.

keep it running (systemd or tmux) and **back up `data-8001/tls.key`**. that's your node's identity, and if you lose it everyone has to trust a new one.

to make your seed the default, put it in `node.py`:

```python
SEEDS = ["https://YOUR.IP:8001#3f9a..."]
```

two or three seeds on different servers is best, so the network survives one going down.

**IPv6?** yep! with `--public-url` the node listens on IPv4 and IPv6 at the same time. put IPv6 addresses in brackets:

```bash
python3 node.py --port 8001 --public-url "https://[2001:db8::1]:8001"
```

**behind a home router?** no port forwarding needed to follow the chain, send or mine. nodes ask their peers for news. you only need an open port if you want *other* nodes to connect to you.

## how it stays safe 🔒

- everything over the network is encrypted (TLS), and nodes are identified by pinned keys instead of certificate companies
- wallet files are locked with scrypt (about 128 MB of memory per password guess, so brute-forcing is painful) + ChaCha20-Poly1305
- every node checks every block and payment from scratch. junk gets dropped and spammers get banned
- rate limits, size limits, connection caps, and anti-eclipse rules (at most 2 untrusted peers from the same /16)
- the miner double-checks that the block it's working on actually pays **you**

**the rules lock 🔐** the shared rules (reward, block time, address format...) are copied into every file and protected by a fingerprint. edit that part and the program **refuses to start**. programs also compare fingerprints with the node they talk to. leave everything between `SHARED RULES BEGIN` and `END` alone! you *can* change `SEEDS`, `CHECKPOINTS` and the node settings below them.

**the honest stuff**
- **51% attacks:** on a tiny network, someone with more hashpower than everyone else combined can rewrite recent blocks. more miners = safer. checkpoints and the 100-block reorg limit protect older history
- **lost phrase + lost wallet/password = lost coins.** nobody can get them back for you
- **clocks:** keep your clock synced (NTP), or your node will reject good blocks
- **Python mining is slow** next to real mining software
- the rules lock stops accidents, but someone determined can edit their own copy. nodes with different rules just won't accept each other's blocks
- not audited. read the code before you trust it!

## your recovery phrase 📝

when you make a wallet you get **24 words** (or 12 with `--words 12`). those words **are** your wallet: with them you can rebuild it anywhere, even if you lose the file and the password.

```bash
python3 wallet.py seed wallet.json      # show them again
python3 wallet.py restore wallet.json   # rebuild from the words
```

typing just the first 4 letters of each word works, capitals don't matter, and if you misspell or swap words the checksum catches it and tells you.

it uses standard BIP39 words (+ SLIP-10 Ed25519). other crypto wallets will accept the phrase, but only NyanCoin's own wallets know NyanCoin addresses.

- write it on **paper**. no screenshots, no emails, no cloud notes
- **anyone who sees your words can take your coins.** nobody legit will ever ask for them
- `NYAN_PASS=...` skips the password prompt for scripts, but other programs can peek at environment variables, so don't use it on a wallet that holds anything you care about

## the GUIs 🪟

**`gui_wallet.py`:** create, restore or open a wallet. it shows your balance, your address with a copy button, history (refreshes every 10s, double-click to copy a txid), send (summary + password first), and settings. it uses the same files as `wallet.py`.

**`gui_miner.py`:** paste your address (or pick your wallet file, it only reads the address), pick a node and how many cores (default: all but one, so your PC stays usable), and hit **Start mining**. you'll see the hashrate, difficulty, your expected time per block, blocks found and your balance.

both need Tkinter, which comes with Python on Windows and macOS. on Debian/Ubuntu: `sudo apt install python3-tk`.

## checkpoints (for network operators)

a checkpoint locks a block in forever. once the network agrees on a block that's safely deep (100+ blocks back):

```bash
python3 wallet.py checkpoint --node https://IP:8001#PIN
# CHECKPOINTS = {1234: "0000ab..."}
```

put that line in `node.py` and share the new file. only add checkpoints *everyone* agrees on, or the network splits!

## something broke? 🔧

| message | what's up |
|---|---|
| `version mismatch: ... different NyanCoin rules` | the program and node are different versions. update both |
| `The shared consensus rules in this file were modified` | someone edited the locked bit. grab a fresh copy |
| `TLS key for HOST:PORT CHANGED` | the server's key changed. if you trust it, delete its entry in `~/.nyancoin/known_hosts.json` |
| `TLS pin mismatch` | the `#PIN` doesn't match that server. check the pin and the address |
| `wrong password (or wallet file corrupted)` | it's exactly what it says |
| `rejected by node (HTTP 400)` | not enough coins, fee too low, or wait for your pending payments to confirm |
| `node unreachable, retrying` | node's down, or the address/port is wrong |
| node stuck at height 0 | it can't reach any peers. check the seed address, pin and firewall |

## where stuff lives 📁

- `data-<port>/chain.jsonl`: the blockchain (public)
- `data-<port>/peers.json`: known peers
- `data-<port>/tls.key` + `tls.crt`: your node's identity (**keep `tls.key` secret!**)
- `~/.nyancoin/known_hosts.json`: remembered server keys (`NYAN_HOME` moves it)
- `wallet.json`: your encrypted wallet

## credits 💖

made by **[PythonScratcher](https://github.com/PythonScratcher)**, co-authored by **Claude** (Anthropic's AI) 🤖🐾

have fun and happy mining! nyaa~ =^･ω･^=
