# LeCatchu v3

![LeCatchu Logo](LeCatchu.png)
[Discord](https://discord.gg/ev6AJzt32X) | [Reddit](https://www.reddit.com/r/LeCatchu/s/AdwugeAmL4) | [YouTube](https://youtube.com/@aertsimon90?si=zaH8BkmmxdbI4ziv) | [Instagram](https://www.instagram.com/ertanmuz/profilecard/?igsh=aWxwb3ZpNDhnbTIx)

### Technical Information

LeCatchu v3 is a lightweight, high-entropy cryptography engine built around an unpredictable shifting algorithm. It is not designed as a standalone encryption method but as a core engine upon which secure systems can be constructed.

Compared to RSA, it offers 2–3 times faster performance and enhanced security. While its efficiency depends on implementation, it is highly optimized for flexibility. Future versions will be ported to C and JavaScript, potentially achieving up to 500x speed improvements without sacrificing functionality—positioning it as a rival to AES in performance.

LeCatchu v3 is the next evolution of the lightweight encryption engine that evolved from v2. It was developed to address a critical security flaw in v2 (improper handling of the `xbase` parameter in the hash stream), while also optimizing performance. After fixing the flaw, a slowdown of approximately 0.0005 seconds was observed in the hash stream, prompting a 1.5x performance boost through hash system enhancements. LeCatchu truly values its users (assuming there are any!).

LeCatchu v3 is currently the latest and non-experimental version of the LeCatchu Engine. In other words, LeCatchu v3 is, for now, the best LeCatchu engine designed for real-world operations.

---

## Overview

LeCatchu v3 builds on v2’s foundation, introducing significant improvements in security and performance based on real-world testing and feedback. Key enhancements include:

1. **Security Fix:**  
   v2’s `hash_stream` function mishandled the `xbase` parameter, leading to inconsistent key streams. v3 resolves this critical vulnerability, ensuring robust encryption.

2. **Performance Optimization:**  
   After fixing the security issue, a 0.0005-second slowdown was detected. This was mitigated by switching to Blake2b and adding caching (`@lru_cache`), resulting in a 1.5x faster hash system.

3. **Speed and Efficiency:**  
   Core functions—encryption, decryption, encoding, and decoding—have been fine-tuned to minimize processing time.

4. **Revamped Hash Algorithm:**  
   Transitioning from SHA-256 to Blake2b with caching, the hash system is now faster and more secure while maintaining per-character key rehashing.

5. **Secure `lestr` and `leval` Functions:**  
   These functions emulate Python’s `repr` and `eval` safely within a JSON framework, eliminating code injection risks.

6. **Robust UTF-8 Handling:**  
   The `encode_direct` and `decode_direct` functions now manage UTF-8 encoding/decoding reliably, preventing common errors like "utf-8 can't decode ??? character."

---

## Evolution from v2 to v3

### What Changed from v2?

- **Critical Security Fix:**  
   In v2, the `hash_stream` function produced inconsistent key streams for `xbase`>1. v3 corrects this by aggregating all `xbase` hashes, enhancing security.

- **Hash System Optimization:**  
   Post-fix slowdown (0.0005 seconds) was addressed by adopting Blake2b and caching, achieving a 1.5x speed increase over v2’s hash system. Users can verify this by reverting to SHA-256 and testing against v2.

- **Performance Boost:**  
   Benchmarks show v3 outperforms v2, particularly in hash-intensive operations like large data and multi-key scenarios.

- **Code Refinement:**  
   Streamlined loops, improved memory management, and better error handling make v3 smoother and more efficient.

### Performance Benchmark Comparisons

Below are benchmark results comparing LeCatchu v2 and v3:

#### Overall Speed Test
- **v2:** 0.016668 seconds  
- **v3:** 0.0159 seconds (~5% improvement)

#### 1024-Byte Data Encryption/Decryption
- **Encryption:**  
  - v2: 0.006999 seconds  
  - v3: 0.006512 seconds  
- **Decryption:**  
  - v2: 0.007011 seconds  
  - v3: 0.006498 seconds  

#### Large-Scale Text Tests (100,000 characters)
- **Encoding:** 0.019889 seconds  
- **Decoding:** 0.046557 seconds  

#### Multi-Key Encryption/Decryption (50 keys)
- **Encryption:** 0.003664 seconds  
- **Decryption:** 0.003599 seconds  

#### Security and Integrity Tests
- **Key Collision Resistance:** Passed  
- **Reverse Character Encoding/Decoding:**  
  - Time: 0.000064 seconds (Passed)  
- **Entropy on Large Data:** 16.519591 (high randomness)  
- **Hash Collision with Complex Keys:** Passed  
- **Differential Cryptanalysis:** Passed  

*Note:* v3’s optimizations offset the post-fix slowdown. To confirm, remove Blake2b and caching, revert to SHA-256, and compare with v2’s hash stream performance.

---

## Key Features in Detail

### Fast and Optimized
v3 delivers high performance with refined loops, efficient memory use, and reduced overhead, excelling even under heavy workloads.

### Revamped Hash Algorithm
Switching to Blake2b with caching ensures faster, secure hashing while preserving per-character key rehashing.

### Enhanced Type-Checking
The `encode` and `decode` functions process only valid inputs, reducing errors and boosting efficiency.

### Secure `lestr` and `leval`
JSON-based serialization/deserialization provides a safe alternative to `repr` and `eval`, minimizing security risks.

### Robust UTF-8 Handling
Improved `encode_direct` and `decode_direct` functions ensure reliable UTF-8 processing and data integrity.

---

## Future Developments

LeCatchu v3 is a significant step forward, but the journey continues. Planned enhancements include:
- **Multi-Key Performance:** Further optimization for multi-key scenarios.  
- **Parallel Processing:** Leveraging multi-threading or async techniques for greater speed.  
- **Salt and IV Integration:** Ensuring unique outputs for repeated encryptions with the same key.  
- **Extended Testing:** Incorporating community feedback for ongoing security and feature improvements.

---

## Conclusion

LeCatchu v3 advances the encryption engine by fixing a critical security flaw from v2 and boosting hash performance by 1.5x. Designed with its users in mind (yes, you!), it offers a fast, secure solution for diverse cryptographic needs. Curious about the optimization? Revert to SHA-256, remove Blake2b caching, and test it against v2—you’ll see the difference.

We invite you to explore, test, and contribute to LeCatchu v3. Your feedback drives this project forward.

**Version:** 3  
**Engine File:** `lecatchu_v3.py`  
**Test Suite:** `lecatchu_v3_test.py`

---

### Shh 🤫 Look Here

Have you seen the mysterious `xbase` values inside LeCatchu?

Well... *that’s actually your second key.*

If your `xbase` is set to `1`, you already gain access to **vigintillions** of unique keys. Pretty wild, right?

**But what if you set it higher?**  
Let’s say `xbase = 50` — now, instead of just swimming through a pool of `10^63` keys,  
you’re diving into an ocean of **`10^512` unique values**.  
That’s no longer "a lot" — that’s *effectively infinite* in the software universe.

And get this: now imagine you’re using **500 multi-keys**,  
each of them built with `xbase = 50`...  
Congratulations.  
You’ve created a crypto-system so chaotic, even chaos gave up trying to understand it.

---

**xbase** is the secret key to the keys.  
The engine behind uniqueness.  
The multiplier of entropy.  
And the cherry on top?  
> LeCatchu's only flaw is that it doesn’t tell you it’s flawless. 😏
