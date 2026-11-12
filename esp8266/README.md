# NyanCoin ESP8266 miner (with Waveshare 2.13" e-Paper V4)

A tiny miner for an ESP8266 board (NodeMCU, Wemos D1 mini, ...) with an optional Waveshare 2.13"
e-Paper V4 screen showing hashrate, block, difficulty, blocks found, balance and expected time per block.

**Honest expectations:** an ESP8266 does roughly 20–60 thousand hashes per second, about 1000× slower than a
PC. It finds blocks while difficulty is low, but once PC miners join it will very rarely win one.

## Safety
- It checks the node's identity against `NODE_PIN` (the same `#PIN` used everywhere else) before trusting it.
- It **rebuilds the block header itself** from the node's small work fields and refuses work unless the node's
  header is byte-for-byte identical, so the block can only ever pay **your** address.
- It never needs your wallet, password or recovery phrase. Only your address.

## Needs
- A node running **node.py 1.1.0+** (adds `/work`, `/submit`, `/pubkey`). The official seed must be updated too.
- The node's host name must have an **IPv4 (A) record**: the ESP8266 is IPv4-only.

## Setup (Arduino IDE)
1. Preferences → Additional boards URLs: `https://arduino.esp8266.com/stable/package_esp8266com_index.json`,
   then Boards Manager → install **esp8266**, and select your board.
2. **Tools → CPU Frequency → 160 MHz** (almost doubles the hashrate).
3. Library Manager: install **GxEPD2** (it pulls in Adafruit GFX) and **ArduinoJson** (version 7).
4. Open `nyancoin_esp8266_miner/nyancoin_esp8266_miner.ino`, fill in the SETTINGS block (WiFi, `ADDRESS`),
   and upload. Open the Serial Monitor at **115200** baud to watch it.

No screen? Set `USE_DISPLAY = false`.

## Wiring (display → ESP8266)

| Display | ESP8266 pin |
|---|---|
| VCC | 3V3 |
| GND | GND |
| DIN | D7 (GPIO13) |
| CLK | D5 (GPIO14) |
| CS | D1 (GPIO5) |
| DC | D0 (GPIO16) |
| RST | **not connected** |
| BUSY | D2 (GPIO4) |

## Troubleshooting
- **Garbled or blank screen:** in the sketch, replace both `GxEPD2_213_GDEY0213B74` with `GxEPD2_213_BN`.
- **Gibberish in the serial monitor / board won't start with the screen attached:** make sure CS and DC are on
  D1 and D0 and RST is unconnected, as above. The boot pins D3/D4/D8 must stay free
  (otherwise the board won't boot or upload), and D6 is used by SPI (garbled screen).
- **"PIN MISMATCH":** `NODE_PIN` is wrong, or something is impersonating the node. Nothing is mined.
- **"node too old" / HTTP 404:** the node needs node.py 1.1.0 or newer.
- **"BAD WORK":** the node sent a block that doesn't pay you the right reward, so it was refused.
- **Resets / out of memory:** the serial log prints free heap every 10 s. TLS needs ~25 KB free.

## How it was tested
The sketch's mining code (pin check, address check, header building, hashing) was compiled on a PC and mined
real blocks against a live node. The board-specific parts (WiFi, TLS, display) weren't compiled for the
ESP8266 here, so report any compile error and it'll get fixed.
