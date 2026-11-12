/*
 * NyanCoin miner for ESP8266 (NodeMCU / Wemos D1 mini) with optional
 * Waveshare 2.13" e-Paper V4 display (250x122, SSD1680 = GxEPD2 "GDEY0213B74").
 *
 * What it does
 *   - joins your WiFi, connects to a NyanCoin node over TLS and checks the node's
 *     identity against NODE_PIN (the same #PIN you use everywhere else)
 *   - asks the node for tiny "work" (block height, previous hash, time, difficulty),
 *     REBUILDS THE BLOCK HEADER ITSELF so the block can only ever pay YOUR address,
 *     and refuses work if the node's header differs by even one byte
 *   - hashes SHA-256 as fast as the chip can, submits solutions, shows stats on the
 *     e-paper screen and the serial monitor (115200 baud)
 *
 * Honest expectations: an ESP8266 does roughly 20-60 thousand hashes per second, about
 * 1000x slower than a PC. It can find blocks while difficulty is low, but once PC miners
 * join it will very rarely win one. It's a fun "my coin runs on a tiny chip" project.
 *
 * Needs a node with the tiny-miner API (/work, /submit, /pubkey): node.py 1.1 or newer.
 *
 * Arduino IDE setup
 *   1. Boards Manager URL: https://arduino.esp8266.com/stable/package_esp8266com_index.json
 *      then install "esp8266" and pick your board (e.g. "LOLIN(WEMOS) D1 R2 & mini").
 *      Tools > CPU Frequency: 160 MHz (almost doubles the hashrate).
 *   2. Library Manager: install "GxEPD2" (also installs Adafruit GFX) and "ArduinoJson" (v7).
 *   3. Fill in the SETTINGS below and upload.
 *
 * Wiring (Waveshare 2.13" module -> ESP8266). Nothing goes on the boot pins D3/D4/D8
 * (GPIO0/2/15): a display tugging on those stops the board booting and uploading.
 * D6 (GPIO12) is avoided too, because SPI takes it over. RST is left unconnected: the
 * screen controller is reset by a software command instead.
 *   VCC -> 3V3     GND -> GND
 *   DIN -> D7 (GPIO13)   CLK -> D5 (GPIO14)   CS -> D1 (GPIO5)
 *   DC  -> D0 (GPIO16)   BUSY -> D2 (GPIO4)   RST -> not connected
 */

#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <WiFiClientSecureBearSSL.h>
#include <ArduinoJson.h>
#include <bearssl/bearssl.h>
#include <GxEPD2_BW.h>
#include <Fonts/FreeSans9pt7b.h>
#include <Fonts/FreeSansBold9pt7b.h>
#include <Fonts/FreeSansBold12pt7b.h>

// ============================== SETTINGS =====================================
const char*    WIFI_SSID   = "your-wifi-name";
const char*    WIFI_PASS   = "your-wifi-password";
const char*    NODE_HOST   = "inter.net.sh";      // needs an IPv4 (A) record: ESP8266 is IPv4-only
const uint16_t NODE_PORT   = 8001;
const char*    NODE_PIN    = "aacf9733d8a238bc0f8a62232e5ab5b804cd3fe80b32e90c58bd70ff52f1fc41";
const char*    ADDRESS     = "NYAN...your address here...";   // rewards go here
const bool     USE_DISPLAY = true;                // false = serial monitor only
// =============================================================================

// Consensus constants (must match NyanCoin's rules: 1 NYAN per block, halving every 10.5M blocks)
static const uint64_t REWARD0 = 100000000ULL;
static const uint32_t HALVING = 10500000UL;

// Display: Waveshare 2.13" V4 = GDEY0213B74 (SSD1680). If the picture is garbled, try GxEPD2_213_BN.
GxEPD2_BW<GxEPD2_213_GDEY0213B74, GxEPD2_213_GDEY0213B74::HEIGHT>
    display(GxEPD2_213_GDEY0213B74(/*CS=D1*/ 5, /*DC=D0*/ 16, /*RST: none*/ -1, /*BUSY=D2*/ 4));

// ---- BEGIN PURE HELPERS (plain C: also compiled and tested on a PC) ----------
static void sha256(const void *data, size_t n, uint8_t out[32]) {
  br_sha256_context c;
  br_sha256_init(&c);
  br_sha256_update(&c, data, n);
  br_sha256_out(&c, out);
}

static void to_hex(const uint8_t *b, size_t n, char *out) {
  static const char *hx = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) { out[2 * i] = hx[b[i] >> 4]; out[2 * i + 1] = hx[b[i] & 15]; }
  out[2 * n] = 0;
}

static bool is_lower_hex(const char *s, size_t n) {
  for (size_t i = 0; i < n; i++)
    if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
  return true;
}

/* NYAN + 40 hex + 4 hex checksum (first 4 hex of sha256 of the 40 hex chars) */
static bool valid_addr(const char *a) {
  if (strlen(a) != 48 || strncmp(a, "NYAN", 4) != 0 || !is_lower_hex(a + 4, 44)) return false;
  uint8_t d[32]; char h[65];
  sha256(a + 4, 40, d);
  to_hex(d, 32, h);
  return strncmp(h, a + 44, 4) == 0;
}

/* decimal text of an unsigned number (no leading zeros, like Python's str(int)) */
static size_t u64_to_dec(uint64_t v, char *out) {
  char tmp[21]; size_t n = 0;
  do { tmp[n++] = (char)('0' + v % 10); v /= 10; } while (v);
  for (size_t i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
  out[n] = 0;
  return n;
}

/* block hash meets difficulty <=> its first `bits` bits are zero */
static bool meets_bits(const uint8_t *d, uint32_t bits) {
  for (uint32_t i = 0; i < 32; i++) {
    if (bits >= 8) { if (d[i]) return false; bits -= 8; }
    else return bits == 0 || (d[i] >> (8 - bits)) == 0;
  }
  return true;
}

static int b64_val(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

/* decodes base64, skipping newlines/whitespace; returns bytes written or 0 on error */
static size_t b64_decode(const char *in, size_t len, uint8_t *out, size_t max) {
  uint32_t acc = 0; int nbits = 0; size_t o = 0;
  for (size_t i = 0; i < len; i++) {
    if (in[i] == '=') break;
    int v = b64_val(in[i]);
    if (v < 0) continue;
    acc = (acc << 6) | (uint32_t)v; nbits += 6;
    if (nbits >= 8) { nbits -= 8; if (o >= max) return 0; out[o++] = (uint8_t)(acc >> nbits); }
  }
  return o;
}

/* Checks the node's public key (PEM) against the pin = sha256 of the key's DER bytes */
static bool pem_matches_pin(const char *pem, const char *pin_hex) {
  const char *B = "-----BEGIN PUBLIC KEY-----", *E = "-----END PUBLIC KEY-----";
  const char *b = strstr(pem, B), *e = strstr(pem, E);
  if (!b || !e || e < b) return false;
  b += strlen(B);
  uint8_t der[512], d[32]; char hx[65];
  size_t n = b64_decode(b, (size_t)(e - b), der, sizeof der);
  if (!n) return false;
  sha256(der, n, d);
  to_hex(d, 32, hx);
  return strcmp(hx, pin_hex) == 0;
}

/* The exact block header text the node hashes (canonical JSON + "|"), built from the
 * small work fields. Paying anyone but `addr` would produce different text. */
static int build_prefix(char *out, size_t cap, uint32_t bits, uint32_t height, const char *prev,
                        uint32_t t, uint64_t reward, const char *addr) {
  char rw[21]; u64_to_dec(reward, rw);
  return snprintf(out, cap,
      "{\"bits\":%lu,\"index\":%lu,\"prev\":\"%s\",\"time\":%lu,\"txs\":[{\"amount\":%s,"
      "\"from\":\"COINBASE\",\"height\":%lu,\"to\":\"%s\"}]}|",
      (unsigned long)bits, (unsigned long)height, prev, (unsigned long)t, rw,
      (unsigned long)height, addr);
}

/* Tries `count` nonces starting at *nonce on top of the header midstate.
 * Returns true (and leaves *nonce at the winner) when one meets the difficulty. */
static bool mine_batch(const br_sha256_context *mid, uint32_t bits, uint32_t *nonce, uint32_t count) {
  uint8_t d[32]; char buf[21];
  for (uint32_t i = 0; i < count; i++) {
    br_sha256_context c = *mid;
    size_t n = u64_to_dec(*nonce, buf);
    br_sha256_update(&c, buf, n);
    br_sha256_out(&c, d);
    if (meets_bits(d, bits)) return true;
    (*nonce)++;
  }
  return false;
}
// ---- END PURE HELPERS --------------------------------------------------------

struct Job {
  bool valid = false;
  char id[17];
  char prev[65];
  uint32_t height = 0, bits = 0, time = 0;
  char prefix[400];
  br_sha256_context mid;
  uint32_t startedMs = 0;
} job;

BearSSL::PublicKey *nodeKey = nullptr;
BearSSL::Session tlsSession;

uint32_t nonce = 0, found = 0, rejected = 0;
uint64_t hashes = 0;
float hashrate = 0;
float balance = -1;
char status[24] = "starting";
int partialUpdates = 0;

uint32_t lastRateMs = 0, lastTipMs = 0, lastDrawMs = 0, lastBalMs = 0;
uint64_t lastRateHashes = 0;

// ------------------------------------------------------------------ display
void fmtDuration(float s, char *out, size_t cap) {
  if (s < 120) snprintf(out, cap, "%.0f s", s);
  else if (s < 7200) snprintf(out, cap, "%.0f min", s / 60);
  else if (s < 172800) snprintf(out, cap, "%.1f h", s / 3600);
  else snprintf(out, cap, "%.0f days", s / 86400);
}

void drawScreen(bool full) {
  if (!USE_DISPLAY) return;
  if (full || partialUpdates >= 15) { display.setFullWindow(); partialUpdates = 0; }  // clears ghosting
  else { display.setPartialWindow(0, 0, display.width(), display.height()); partialUpdates++; }
  char line[48];
  display.firstPage();
  do {
    display.fillScreen(GxEPD_WHITE);
    display.setTextColor(GxEPD_BLACK);
    display.setFont(&FreeSansBold9pt7b);
    display.setCursor(2, 15);
    display.print("NyanCoin miner");
    int16_t x1, y1; uint16_t w, h;
    display.getTextBounds(status, 0, 0, &x1, &y1, &w, &h);
    display.setCursor(display.width() - w - 4, 15);
    display.print(status);
    display.drawFastHLine(0, 21, display.width(), GxEPD_BLACK);

    display.setFont(&FreeSansBold12pt7b);
    display.setCursor(2, 46);
    if (hashrate >= 1000) snprintf(line, sizeof line, "%.1f kH/s", hashrate / 1000);
    else snprintf(line, sizeof line, "%.0f H/s", hashrate);
    display.print(line);

    display.setFont(&FreeSans9pt7b);
    display.setCursor(2, 66);
    snprintf(line, sizeof line, "Block %lu   diff %lu bits", (unsigned long)job.height, (unsigned long)job.bits);
    display.print(line);
    display.setCursor(2, 86);
    if (balance >= 0) snprintf(line, sizeof line, "Found %lu   %.2f NYAN", (unsigned long)found, balance);
    else snprintf(line, sizeof line, "Found %lu", (unsigned long)found);
    display.print(line);
    display.setCursor(2, 106);
    if (hashrate > 0 && job.bits) {
      char d[16]; fmtDuration((float)(1ULL << job.bits) / hashrate, d, sizeof d);
      snprintf(line, sizeof line, "~%s per block", d);
    } else snprintf(line, sizeof line, "%s", WiFi.isConnected() ? WiFi.localIP().toString().c_str() : "no WiFi");
    display.print(line);

    display.setFont(nullptr);                          // tiny built-in font for the address
    display.setCursor(2, 113);
    snprintf(line, sizeof line, "%.14s...%.6s", ADDRESS, strlen(ADDRESS) > 6 ? ADDRESS + strlen(ADDRESS) - 6 : "");
    display.print(line);
  } while (display.nextPage());
  display.powerOff();
  lastDrawMs = millis();
}

void setStatus(const char *s, bool redraw = false) {
  strncpy(status, s, sizeof status - 1);
  status[sizeof status - 1] = 0;
  Serial.printf("[status] %s\n", s);
  if (redraw) drawScreen(false);
}

// ------------------------------------------------------------------ network
void ensureWiFi() {
  if (WiFi.status() == WL_CONNECTED) return;
  setStatus("WiFi...", true);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 30000) delay(250);
  if (WiFi.status() == WL_CONNECTED) Serial.printf("WiFi OK, IP %s\n", WiFi.localIP().toString().c_str());
}

// Fetch the node's public key without trusting it, then accept it only if it matches NODE_PIN.
bool pinNode() {
  BearSSL::WiFiClientSecure cl;
  cl.setInsecure();                                   // safe: the key is checked against the pin below
  HTTPClient http;
  http.setTimeout(15000);
  if (!http.begin(cl, NODE_HOST, NODE_PORT, "/pubkey", true)) return false;
  int code = http.GET();
  String body = code == 200 ? http.getString() : String();
  http.end();
  if (code != 200) { Serial.printf("/pubkey failed: HTTP %d\n", code); return false; }
  JsonDocument doc;
  if (deserializeJson(doc, body)) return false;
  const char *pem = doc["pem"];
  if (!pem) { Serial.println("node too old: update node.py to 1.1+"); return false; }
  if (!pem_matches_pin(pem, NODE_PIN)) {
    Serial.println("!!! NODE PIN MISMATCH - wrong NODE_PIN, or someone is impersonating the node");
    setStatus("PIN MISMATCH", true);
    return false;
  }
  delete nodeKey;
  nodeKey = new BearSSL::PublicKey(pem);
  Serial.println("Node identity verified (pin OK)");
  return true;
}

// HTTPS request to the node, which must present the pinned key. GET when body is null.
bool api(const char *path, const char *body, JsonDocument &doc) {
  BearSSL::WiFiClientSecure cl;
  cl.setKnownKey(nodeKey);
  cl.setSession(&tlsSession);                         // TLS session resumption: much faster reconnects
  HTTPClient http;
  http.setTimeout(15000);
  if (!http.begin(cl, NODE_HOST, NODE_PORT, path, true)) return false;
  int code;
  if (body) {
    http.addHeader("Content-Type", "application/json");
    code = http.POST((uint8_t *)body, strlen(body));
  } else {
    code = http.GET();
  }
  bool ok = false;
  if (code == 200) ok = !deserializeJson(doc, http.getString());
  else Serial.printf("node %s -> HTTP %d\n", path, code);
  http.end();
  return ok;
}

bool getWork() {
  char path[80];
  snprintf(path, sizeof path, "/work?addr=%s", ADDRESS);
  JsonDocument doc;
  if (!api(path, nullptr, doc)) return false;
  const char *id = doc["job"], *prev = doc["prev"], *prefix = doc["prefix"];
  uint32_t height = doc["height"], bits = doc["bits"], t = doc["time"];
  if (!id || !prev || !prefix || strlen(id) != 16 || strlen(prev) != 64 || !is_lower_hex(prev, 64)
      || bits < 20 || bits > 60 || height == 0) {
    Serial.println("node sent malformed work");
    return false;
  }
  uint64_t rw = REWARD0 >> (height / HALVING);
  int n = build_prefix(job.prefix, sizeof job.prefix, bits, height, prev, t, rw, ADDRESS);
  if (n <= 0 || (size_t)n >= sizeof job.prefix || strcmp(job.prefix, prefix) != 0) {
    Serial.println("!!! node's block doesn't match ours (wrong payout or reward) - refusing it");
    setStatus("BAD WORK");
    job.valid = false;
    return false;
  }
  strcpy(job.id, id);
  strcpy(job.prev, prev);
  job.height = height; job.bits = bits; job.time = t;
  br_sha256_init(&job.mid);
  br_sha256_update(&job.mid, job.prefix, n);         // hash the header once; only the nonce changes
  job.startedMs = millis();
  job.valid = true;
  nonce = RANDOM_REG32;                               // random start: several ESPs won't overlap
  return true;
}

void submit(uint32_t winner) {
  char body[64];
  snprintf(body, sizeof body, "{\"job\":\"%s\",\"nonce\":%lu}", job.id, (unsigned long)winner);
  JsonDocument doc;
  if (api("/submit", body, doc)) {
    const char *r = doc["result"] | "?";
    if (doc["ok"] | false) { found++; Serial.printf("*** FOUND BLOCK %lu! ***\n", (unsigned long)job.height); }
    else { rejected++; Serial.printf("block %lu not accepted: %s\n", (unsigned long)job.height, r); }
  }
  job.valid = false;
  lastBalMs = 0;                                      // refresh balance soon
  drawScreen(false);
}

void checkTip() {
  JsonDocument doc;
  if (api("/info", nullptr, doc)) {
    const char *tip = doc["tip"];
    if (tip && strcmp(tip, job.prev) != 0) job.valid = false;   // someone found the block first
  }
}

void refreshBalance() {
  char path[80];
  snprintf(path, sizeof path, "/balance/%s", ADDRESS);
  JsonDocument doc;
  if (api(path, nullptr, doc)) balance = doc["balance"] | -1.0f;
  lastBalMs = millis();
}

// ------------------------------------------------------------------ main
void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("\nNyanCoin ESP8266 miner");
  if (USE_DISPLAY) {
    display.init(115200, true, 2, false);             // 2 ms reset pulse suits Waveshare boards
    display.setRotation(1);                            // landscape 250x122
    drawScreen(true);
  }
  if (!valid_addr(ADDRESS)) {
    Serial.println("ADDRESS is not a valid NyanCoin address - fix the SETTINGS and re-upload.");
    setStatus("BAD ADDRESS", true);
    while (true) delay(1000);
  }
}

void loop() {
  ensureWiFi();
  if (WiFi.status() != WL_CONNECTED) { delay(2000); return; }
  if (!nodeKey) {
    setStatus("node...", true);
    if (!pinNode()) { delay(30000); return; }
  }
  if (!job.valid) {
    if (!getWork()) { setStatus("no work", true); delay(10000); return; }
    setStatus("mining");
  }

  if (mine_batch(&job.mid, job.bits, &nonce, 2000)) {
    hashes += 1;
    submit(nonce);
    return;
  }
  hashes += 2000;                                      // loop() returning lets WiFi/watchdog run

  uint32_t now = millis();
  if (now - lastRateMs >= 10000) {
    hashrate = (hashes - lastRateHashes) * 1000.0f / (now - lastRateMs);
    lastRateHashes = hashes; lastRateMs = now;
    Serial.printf("%.1f kH/s  block %lu  diff %lu  found %lu  heap %u\n", hashrate / 1000,
                  (unsigned long)job.height, (unsigned long)job.bits, (unsigned long)found, ESP.getFreeHeap());
  }
  if (now - lastTipMs >= 15000) { lastTipMs = now; checkTip(); }
  if (now - job.startedMs >= 60000) job.valid = false;            // fresh timestamp
  if (now - lastBalMs >= 120000 || lastBalMs == 0) refreshBalance();
  if (now - lastDrawMs >= 30000) drawScreen(false);
}
