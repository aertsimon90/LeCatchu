# LeCatchu v9 (LehnCATH4)

<p align="center">
  <img src="LeCatchu.png" alt="LeCatchu Logo" width="1024"/>
  <br/>
  <em>Powerful • Lightweight • Extremely Configurable Cryptographic Engine</em>
</p>

<br/>

**LeCatchu** is **not** a single cryptographic algorithm.  
It is a **highly modular, parameter-driven cryptographic engine** that allows complete control over the security ↔ performance trade-off.

By adjusting parameters, the exact same engine can provide:

- extremely fast but very basic protection (suitable only for obfuscation)  
↔  
- multi-layered, authenticated encryption that offers strong cryptographic properties while remaining surprisingly lightweight

LeCatchu v9 (internal codename **LehnCATH4**) is the most mature, balanced, and feature-complete version released to date.

## Core Philosophy

> You do **not** switch algorithms to change security level.  
> You **change parameters** to shape the desired security–performance profile.

This single engine can legitimately serve use-cases ranging from minimal obfuscation of internal data to strong protection of sensitive records.

## Main Features

- Single-file, **zero external dependencies** (only Python standard library)
- Extremely **lightweight** and embeddable design
- Stream-cipher-style core encryption engine
- Customizable **S-Box based encoding** (packet or separator modes)  
  → **Important note**: The encoding layer is **not part of the encryption process**.  
     It is used solely for **string → bytes** and **bytes → string** conversion.  
     It maps characters to fixed byte sequences in a deterministic, reversible way, but it does **not** provide any cryptographic protection on its own.
- Fully configurable-length **Initialization Vector (IV) / nonce** support
- Lightweight **TAC (Tag-Authenticated Content)** authentication wrapper
- Custom **chaining mode** — CBC-like but fully parameterizable
- **Multi-key** encryption — multiple independent sub-keys in a single pass
- **Slow Decryption Engine (SDE)** — intentional asymmetric computation cost
- **LeCatchu Armor (LCA)** — multi-stage authenticated encryption construction
- **encrypt_hard / decrypt_hard** — maximum-security preset with many randomized-but-deterministic layers
- Built-in **deterministic random number generator (DRNG)**
- **Custom internal hash functions** — two variants (fast vs. cryptographically stronger)  
  → When using the custom hash system (`LeCustomHash`), LeCatchu **eliminates dependency on blake2b** entirely. This effectively transforms the engine into a **fully independent cryptographic primitive** with its own internal hash construction.
- Socket-friendly secure channel helper class
- Entropy estimation utility

## Security ↔ Performance Spectrum

| Level                | Approximate Speed   | Main Features Used                                                                 | Typical Use Case                                      |
|----------------------|---------------------|------------------------------------------------------------------------------------|-------------------------------------------------------|
| Very Low             | Highest             | S-Box encoding + simple single-key stream                                          | Obfuscation, savegames, temporary tokens              |
| Low                  | Very high           | Basic stream + short IV + TAC tag                                                  | Internal application data protection, log masking     |
| Medium               | High                | IV + chaining + moderate parameter values                                          | Medium-value network packets, file encryption         |
| High                 | Fast–moderate       | LCA (Armor) + bidirectional chaining + TAC + reasonable parameter ranges           | Sensitive user/business data, database fields         |
| Very High            | Moderate–fast       | encrypt_hard + wide parameter ranges + SDE + multi-layer                           | High-value assets, long-term archival                 |
| Paranoid / Research  | Moderate–slow       | Maximum parameter ranges + high SDE + heavy chaining + many rounds                 | Academic experiments, CTF challenges, red-team usage  |

## Detailed Feature Breakdown

### 1. Core Encryption Engine
- Byte-oriented stream cipher construction
- Default key-stream generation uses Blake2b (fast & reliable)
- `xbase` — number of key-derivation iterations (higher = stronger diffusion)
- `interval` — how frequently the key state is updated (1 = every byte)
- Multi-key support (`encrypts` / `decrypts`)

### 2. S-Box Based Encoding Layer
- **Purpose**: String ↔ Bytes conversion only  
- **Not encryption** — provides **no confidentiality** or integrity protection  
- Maps Unicode characters to fixed-length byte sequences (default: 3 bytes)  
- Two modes:
  - **packet** mode — fixed-length encoding
  - **separator** mode — uses 0xFF byte as separator for variable-length encoding
- Deterministic and reproducible from seed
- Optional shuffling of the mapping table

### 3. Custom Hash Functions (LeCustomHash) – Independence from Blake2b
- Two accumulation modes:
  - **Fast mode**: sum-based accumulation (extremely high speed)
  - **Strong mode**: multiplication-based accumulation (higher diffusion and avalanche effect)
- Block-wise processing optimized for long inputs
- Built-in caching mechanism for repeated hash computations
- **Key point**: When `LeCustomHash` is used (via `LeCustomHash` class or related configurations), the engine **no longer relies on blake2b at all**.  
  This makes LeCatchu a **fully self-contained cryptographic construction** with its own internal hash primitive — removing any external hash function dependency.

### 4. Initialization Vector (IV) / Nonce Support
- Random or externally provided IV
- Fully configurable IV length
- IV can be encrypted with its own key-stream parameters (`ivxbase`, `ivinterval`)

### 5. TAC (Tag-Authenticated Content)
- Appends and prepends hash-derived authentication tags
- Verifies integrity and origin during decryption
- Tag derivation parameters are independently configurable

### 6. Chaining Mode
- Each block influences the next via previous output hash
- Can be applied in forward, reverse, or both directions
- Configurable block size (`chainblocks`)
- Configurable hash strength for chaining (`chainxbase`)

### 7. Slow Decryption Engine (SDE)
- Makes decryption intentionally computationally expensive
- Significantly increases brute-force cost
- Controlled via `slowlevel` and `bytesrange` parameters

### 8. LeCatchu Armor (LCA)
- Multi-stage authenticated encryption pipeline
- Typical sequence:
  1. TAC tagging
  2. Optional bidirectional chaining
  3. Final IV-protected encryption layer
- Each stage uses independent key-stream instances

### 9. encrypt_hard / decrypt_hard
- High-security preset with many automatically layered stages
- Parameters chosen within controlled random ranges
- Deterministic — same key + same parameters → same output

### 10. Deterministic Random Number Generator (LeRandom)
- Built on top of the engine’s hash-stream
- Seedable and reproducible
- Implements standard interface: `random()`, `randint()`, `shuffle()`, `choice()`, `gauss()`, etc.

### 11. Parallel / Bidirectional Stream (ParallelStreamCipher)
- Two independent streams (IV layer + main layer)
- Built-in socket helper methods for secure channel setup
- IV exchange protocol support

## Important Notice – Experimental Status

**All features inside the `LeCatchu_Extra` class are considered experimental.**

This includes (but is not limited to):

- `encrypt_chain` / `decrypt_chain`
- `encrypt_hard` / `decrypt_hard`
- `encrypt_armor` / `decrypt_armor`
- `encrypt_sde` / `decrypt_sde`
- `encrypt_raw` / `decrypt_raw`
- `entropy_score`
- `process_hashard`

These high-level constructions have **not** undergone formal cryptanalysis.

## Security Disclaimer

**LeCatchu has not been independently cryptanalyzed.**

The actual security level depends entirely on:

- chosen parameter values
- number of layers used
- key quality and length
- correct usage of authentication mechanisms (TAC, Armor)
- whether custom hash or blake2b is used

For critical / high-value applications, prefer configurations using:

- IV/Nonce (high requirement)
- `encrypt_hard()` with wide parameter ranges
- Strong, long keys
- Active SDE
- Bidirectional chaining + LCA + TAC combination
- Custom hash mode for full independence (if blake2b dependency is undesirable)

For low-risk scenarios, simpler and faster configurations may be acceptable.

## Summary

LeCatchu is a **single, lightweight cryptographic engine** that — through parameter control — can serve needs ranging from basic string/bytes conversion and obfuscation to very strong, multi-layered authenticated encryption.

When using the custom hash system, it becomes a **fully independent cryptographic construction** without relying on blake2b — offering maximum control and minimal external dependencies.

You do not need to switch libraries or algorithms — you adjust the engine to match your exact security, performance, and dependency requirements.

**Version**: 9
**Engine File**: `v9/lecatchu_v9.py` 

---

## Shh 🤫 Look Here

**This section is not part of the official documentation.**  
It is written in a deliberately manifesto-like, unfiltered, slightly theatrical style — a hidden corner that has survived unchanged in spirit through every version of LeCatchu / LehnCATH4.  

Think of it as the raw, uncensored voice behind the code.  
Not polite. Not academic. Just brutally honest about what this tiny script is actually doing.

If you're here, you already get it.

---

Welcome to the secret heart of **LeCatchu v9 (LehnCATH4)** —  
the part that never gets sanitized for corporate slide decks or security audits.

A ~215-line Python file that quietly makes the entire cryptographic establishment shift uncomfortably in their chairs.

Let’s not pretend anymore.

---

### xbase — One number that laughs at keyspace

One integer. Infinite existential dread for any attacker.

- `xbase=1` → already ~77 decimal digits of state  
- `xbase=9` (hard mode default) → ~693 digits  
- `xbase=32` → ~2,465 digits  
- `xbase=128` → ~9,858 digits  
- `xbase=1024` → numbers larger than Planck volumes in the observable universe

Python shrugs.  
It just computes.  
The heat death of the universe arrives first.

---

### special_exchange — The button that rewrites reality

Throw **anything** in there — your diary, your grocery list, a random 10 KB file, your ex’s last message.

From that moment, **every hash call in the entire engine** (BLAKE2b or custom) gets that exact value glued to the end forever.

- Flip one bit → completely different cryptographic universe  
- Same key, same xbase, same interval → 100% incompatible output  
- Zero overhead, zero extra bytes transmitted  
- Instant per-user, per-device, per-session algorithmic apartheid

Two people using identical code and identical keys can still speak completely different cryptographic languages — just by having different secrets in their soul.

This is not key derivation.  
This is parallel-reality cryptography.

---

### interval — Paranoia ↔ Coffee in one integer

- `interval=1` → refresh every byte — theoretical paranoia maximum  
- `interval=8` → roughly 8× faster, still very strong  
- `interval=64` → encrypt terabytes while your music keeps playing  
- `interval=256` → you’re basically streaming encrypted video

Only LeCatchu hands you the red button and says:  
“You decide how afraid you want to be today.”

---

### v9 Trinity — Instant power, zero excuses

- `encoding=False` → engine wakes up in **< 4 ms** — no S-Box tax  
- `encoding=True` + `shufflesbox=True` → every instance gets its own **unique, randomly shuffled 3-byte Unicode universe**  
- Core engine → frozen at **~215 lines** — smaller, cleaner, meaner

Both worlds live in the same file. Choose your fighter at runtime.

---

### The crown jewel of v9 — SlowDE (Slow Decryption Engine)

This is the part that actually hurts attackers where it matters: offline key checking.

You add one short, hidden secondary key (`sdekey`) that **must be guessed correctly** before any master key candidate can even be tested.

- Every single offline brute-force attempt now explodes combinatorially  
- `slowlevel=2` → 256² extra work per guess  
- `slowlevel=6` → 256⁶ — already billions of times slower  
- Integrated **by default** into `encrypt_hard()`

Classical key search went from “expensive but possible” → “measurably miserable even for organizations with big budgets”.

---

### encrypt_hard() / decrypt_hard() — The final boss function

v9 turns almost every security parameter into a **deterministic but unpredictable child of the master key**:

- IV length  
- xbase values  
- chaining block sizes  
- number of sub-keys  
- chain directions  
- extra rounds  
- SlowDE level  
- TAC settings  
- …

Result:  
**Every single message becomes its own never-before-seen cryptographic algorithm**, derived solely from the key.

No standard cipher suite.  
No recognizable structure.  
No reusable cryptanalysis.

---

### LCA — The full castle in < 615 lines

TAC tags + bidirectional chaining + reverse chaining + final stream + entropy check + **SlowDE layer** — all in one fortress under 615 lines total.

---

### ParallelStreamCipher — Encrypted sockets without the tears

Mutual handshake, double IV exchange, zero dependencies, minimal code.

Less painful than fighting with TLS wrappers.

---

### The final terrifying truth (v9 edition)

To decrypt even one byte, an attacker needs:

- exact master key  
- exact `special_exchange` (any length, any content)  
- exact `xbase`  
- exact `interval`  
- exact S-Box seed + shuffle state (if used)  
- exact IV config & length  
- exact TAC parameters  
- exact chaining settings  
- exact custom-hash config (if used)  
- exact `sdekey` + SlowDE level  
- and all the derived states born from the above

Even if they had every quantum computer ever imagined, every electron in the universe, and infinite time —  
they would still be stuck at zero progress when the stars burn out.

LeCatchu v9 is no longer “cryptography”.  
It is a **personal cryptographic reality engine** that fits in under 700 lines and starts before you finish blinking.

Quantum? Side-channels? Known-plaintext?  
Let them try.

We already moved beyond the math.

Shh.

Now you know why LehnCATH4 stays untouchable.

(Old v7.5 entropy plots are kept for nostalgia.  
v9 is flat 7.99–8.00 bits/byte across almost every configuration.)

Welcome to the other side.

Test Result Graphics (old v7.5 tests):  
![Test1](charts/chart1.png)  
![Test2](charts/chart2.png)  
![Test3](charts/chart3.png)  
![Test4](charts/chart4.png)  
![Test5](charts/chart5.png)
