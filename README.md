# NyanCoin

NyanCoin is a small peer-to-peer proof-of-work cryptocurrency I made for fun.

It has nodes that sync with each other, wallets with recovery phrases, and miners for PC, Android and the ESP8266 (with an e-ink screen). All network traffic is encrypted, and every node checks every block, so nobody can make up coins.

> This is a hobby project. It has been tested, but it hasn't been audited and the network is small.
> Don't put money you care about into it.

<p>
<img src="android/screenshots/2_wallet.png" width="200"> <img src="android/screenshots/3_mine.png" width="200">
<img src="android/screenshots/4_settings.png" width="200">
</p>

## What's in the repo

| File | For | What it does |
|---|---|---|
| `node.py` | server operators | stores and checks the blockchain, talks to other nodes. It doesn't mine and holds no keys |
| `wallet.py` | everyone | makes a wallet, checks balances, sends coins |
| `miner.py` | miners | mines on all your CPU cores |
| `gui_wallet.py` | desktop users | the wallet with a window |
| `gui_miner.py` | desktop users | the miner with a window |
| `android/` | phone users | native Android wallet and miner |
| `esp8266/` | tinkerers | Arduino miner for an ESP8266 with an optional Waveshare 2.13" e-ink V4 screen |

Each Python file works on its own, so you can give someone just `wallet.py`.

You need Python 3 (built on 3.13) and `pip install cryptography`. Nothing else.

## Quick start

The wallet and miner connect to the main seed node, `inter.net.sh`, by default. Its key is pinned in the code, so a fake node can't pretend to be it. You don't need to run your own node.

```bash
pip install cryptography

# 1. make a wallet (it shows your 24 words, then asks for a password of 12+ characters)
python3 wallet.py new wallet.json
python3 wallet.py show wallet.json            # prints your address: NYAN...

# 2. mine (rewards go to your address)
python3 miner.py --address NYAN...youraddress

# 3. check your coins and spend them
python3 wallet.py history wallet.json
python3 wallet.py send --wallet wallet.json --to NYAN...friend --amount 1.5
python3 wallet.py status
```

If you'd rather use a window, run `python3 gui_wallet.py` and `python3 gui_miner.py`.

## Android app

A native app written in Kotlin with Jetpack Compose. It isn't a website in a wrapper: it signs payments, mines and checks node keys itself.

- Create a new wallet, or restore one from your words (the first 4 letters of each word are enough)
- Balance, history, send (asks for your password) and receive (with a QR code)
- Mines on the phone's CPU, with a thread slider and a keep-screen-on option
- Uses the same wallet file format as `wallet.py`, so the phone and PC wallets can open each other's files

**Download:** [NyanCoin-1.0.0.apk](https://glide.pythonscratcher.net/files/afjiQP-NyanCoin-1.0.0.apk). When Android asks, allow "install unknown apps".

To build it yourself (JDK 17 and the Android SDK):

```bash
cd android
gradle assembleRelease      # -> app/build/outputs/apk/release/app-release.apk
gradle testDebugUnitTest    # checks the Kotlin code against test vectors made by the Python code
```

Phones mine much more slowly than PCs, and Android slows apps down once the screen is off.

## ESP8266 miner

A miner for an ESP8266 board (NodeMCU, Wemos D1 mini and similar). The optional Waveshare 2.13" e-ink V4 screen shows your balance, hashrate, block, difficulty, blocks found and expected time per block.

An ESP8266 manages roughly 20 to 60 thousand hashes per second, about 1000 times slower than a PC. It finds blocks while the difficulty is low, but once PCs are mining it will rarely win one.

It only needs your address, never your wallet, password or recovery phrase. It checks the node's `NODE_PIN` before trusting it, and it rebuilds the block header itself, refusing any work that doesn't pay your address.

**You need:**
- a node running `node.py` 1.1.1 or newer
- a node host name with an IPv4 (A) record, because the ESP8266 can't do IPv6

**Setup (Arduino IDE):**
1. In Preferences, add `https://arduino.esp8266.com/stable/package_esp8266com_index.json` as a board URL. Then install **esp8266** in Boards Manager and select your board.
2. Set **Tools → CPU Frequency → 160 MHz**. It almost doubles the hashrate.
3. In Library Manager, install **GxEPD2** (it also installs Adafruit GFX) and **ArduinoJson** (version 7).
4. Open `esp8266/nyancoin_esp8266_miner/nyancoin_esp8266_miner.ino`, fill in the SETTINGS block (WiFi and `ADDRESS`), and upload. Serial Monitor runs at 115200 baud.

No screen? Set `USE_DISPLAY = false`.

**Wiring (display → ESP8266):**

| Display | ESP8266 pin |
|---|---|
| VCC | 3V3 |
| GND | GND |
| DIN | D7 (GPIO13) |
| CLK | D5 (GPIO14) |
| CS | D1 (GPIO5) |
| DC | D0 (GPIO16) |
| RST | D6 (GPIO12) |
| BUSY | D2 (GPIO4) |

Leave D3, D4 and D8 free. They're boot pins, and the board won't boot or upload if the display uses them. The screen redraws every 30 seconds and whenever something changes (like a found block), and it fully clears at boot. For more help, see `esp8266/README.md`.

## How the coin works

| | |
|---|---|
| Block reward | 1 NYAN, halving every 10,500,000 blocks (about every 3.3 years) |
| Max supply | just under 21,000,000 NYAN. No premine; the genesis block is empty |
| Block time | aims for 10 seconds; difficulty adjusts every 10 blocks |
| Smallest amount | 0.00000001 NYAN |
| Addresses | `NYAN` + 44 characters, with a checksum that catches typos |
| Fees | go to the miner of the block. The minimum a node will relay is 0.00001 NYAN |
| Signatures | Ed25519 |
| Network id | `nyancoin-2` |

**What the fee is for:** it pays the miner who puts your payment into a block. When blocks are full, miners take the highest fees first. The default of 0.0001 is plenty for now.

## wallet.py commands

| Command | What it does |
|---|---|
| `new FILE [--words 12\|24]` | makes a new wallet with a recovery phrase |
| `seed FILE` | shows your recovery phrase again (needs the password) |
| `restore FILE` | rebuilds a wallet from your words |
| `show FILE` | prints your address (no password needed) |
| `balance ADDRESS` | shows the balance and next nonce |
| `history ADDRESS_OR_FILE [--limit N]` | lists payments in and out, rewards, pending payments and confirmations |
| `tx TXID` | says whether a payment is pending, confirmed or unknown |
| `send --wallet FILE --to ADDRESS --amount N [--fee F]` | sends coins (default fee 0.0001) |
| `status` | shows what the node is doing |
| `checkpoint [--height H]` | prints a `CHECKPOINTS` line (see below) |

All commands take `--node URL` to use a different node.

**node.py** options: `--port`, `--public-url`, `--peers`, `--host`, `--data`, `--tick`, `--allow-local-peers`, `--max-reorg`, `--insecure` (plain HTTP, for testing only).
**miner.py** options: `--address` (required), `--node`, `--procs`.

## Running your own node

Running a node helps the network and keeps your lookups private:

```bash
python3 node.py --port 8001
```

It finds the seed node on its own. Then add `--node https://127.0.0.1:8001` to your wallet and miner commands, or set the node in the GUI settings. A status page runs at `https://127.0.0.1:8001/`. Your browser will warn about the self-signed certificate, which is expected.

### Running a public seed node

On a VPS, open the port in the firewall, then run:

```bash
python3 node.py --port 8001 --public-url https://YOUR.IP.OR.DOMAIN:8001
```

It prints something like:

```
TLS pin: 3f9a...
Share this seed address: https://YOUR.IP:8001#3f9a...
```

The `#3f9a...` part is the pin, a fingerprint of the node's key. Anyone using the address with the pin knows they're talking to your node and not an impostor.

Keep the node running (with systemd or tmux), and back up `data-8001/tls.key`. That file is your node's identity; if you lose it, everyone has to trust a new key.

To make your node a default seed, add it in `node.py`:

```python
SEEDS = ["https://YOUR.IP:8001#3f9a..."]
```

Two or three seeds on different servers are best, so the network keeps working if one goes down.

**IPv6:** with `--public-url` set, the node listens on IPv4 and IPv6 at the same time. Put IPv6 addresses in brackets:

```bash
python3 node.py --port 8001 --public-url "https://[2001:db8::1]:8001"
```

**Behind a home router:** you don't need port forwarding to follow the chain, send coins or mine, because nodes ask their peers for updates. You only need an open port if you want other nodes to connect to you.

## Security

- All network traffic is encrypted with TLS. Nodes are identified by pinned keys instead of certificate authorities.
- Wallet files are encrypted with scrypt (about 128 MB of memory per password guess, which makes brute-forcing slow) and ChaCha20-Poly1305.
- Every node checks every block and payment from scratch. Invalid data is dropped and peers that send it are banned.
- Nodes have rate limits, size limits, connection caps and anti-eclipse rules (at most 2 untrusted peers from the same /16).
- Miners check that the block they're working on pays their own address.

**Rules lock:** the shared rules (reward, block time, address format and so on) are copied into every file and protected by a fingerprint. If that section is edited, the program refuses to start. Programs also compare fingerprints with the node they connect to. Don't edit anything between `SHARED RULES BEGIN` and `END`. You can change `SEEDS`, `CHECKPOINTS` and the node settings below them.

## Recovery phrase

A new wallet comes with 24 words (or 12 with `--words 12`). The words are your wallet: with them you can rebuild it anywhere, even after losing the file and the password.

```bash
python3 wallet.py seed wallet.json      # show the words again
python3 wallet.py restore wallet.json   # rebuild a wallet from the words
```

When restoring, the first 4 letters of each word are enough and capitals don't matter. The checksum catches misspelled or swapped words and tells you what's wrong.

It uses the standard BIP39 word list with SLIP-10 Ed25519 keys. Other crypto wallets will accept the phrase, but only NyanCoin's wallets know NyanCoin addresses.

- Write the words on paper. Don't screenshot, email or save them in a cloud note.
- Anyone who sees your words can take your coins. Nobody legitimate will ever ask for them.
- `NYAN_PASS=...` skips the password prompt in scripts. Other programs on the same computer can read environment variables, so don't use it for a wallet that holds anything valuable.

## The GUIs

**gui_wallet.py:** create, restore or open a wallet. It shows your balance, your address with a copy button, your history (refreshed every 10 seconds; double-click a payment to copy its transaction ID), a send screen (it shows a summary and asks for the password first) and settings. It uses the same wallet files as `wallet.py`.

**gui_miner.py:** paste your address, or pick your wallet file (it only reads the address). Then choose a node and how many CPU cores to use, and press **Start mining**. The default is all cores but one, so your PC stays usable. It shows the hashrate, difficulty, your expected time per block, blocks found and your balance.

Both need Tkinter, which comes with Python on Windows and macOS. On Debian/Ubuntu, run `sudo apt install python3-tk`.

## Checkpoints (for network operators)

A checkpoint permanently locks in a block. Once the network agrees on a block that's safely deep (100+ blocks back), run:

```bash
python3 wallet.py checkpoint --node https://IP:8001#PIN
# CHECKPOINTS = {1234: "0000ab..."}
```

Put that line in `node.py` and share the updated file. Only add checkpoints the whole network agrees on, or the network will split.

## Troubleshooting

| Message | Meaning |
|---|---|
| `version mismatch: ... different NyanCoin rules` | The program and the node are different versions. Update both. |
| `The shared consensus rules in this file were modified` | The locked section was edited. Download a fresh copy. |
| `TLS key for HOST:PORT CHANGED` | The server's key changed. If you trust the change, delete its entry in `~/.nyancoin/known_hosts.json`. |
| `TLS pin mismatch` | The `#PIN` doesn't match the server. Check the pin and the address. |
| `wrong password (or wallet file corrupted)` | The password is wrong, or the wallet file has been changed. |
| `rejected by node (HTTP 400)` | You don't have enough coins or the fee is too low. If you have pending payments, wait for them to confirm. |
| `node unreachable, retrying` | The node is down, or the address or port is wrong. |
| Node stuck at height 0 | It can't reach any peers. Check the seed address, the pin and the firewall. |

## Where files are kept

- `data-<port>/chain.jsonl`: the blockchain (public)
- `data-<port>/peers.json`: known peers
- `data-<port>/tls.key` and `tls.crt`: your node's identity (keep `tls.key` private)
- `~/.nyancoin/known_hosts.json`: remembered server keys (set `NYAN_HOME` to move it)
- `wallet.json`: your encrypted wallet

## Credits

Made by [PythonScratcher](https://github.com/PythonScratcher), co-authored by Claude (Anthropic's AI).
