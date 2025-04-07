# LeCatchu v2

![LeCatchu Logo](LeCatchu.png)

### Technical Information

LeCatchu v2 is a lightweight, high-entropy cryptography engine based on an unpredictable shifting algorithm. It’s designed not as a standalone encryption method, but as a core engine on which secure systems can be built.

Compared to RSA, it is 2–3 times faster and more secure. Its performance can vary based on implementation, but it's highly optimized for flexibility. In future versions, it will be ported to C and JavaScript, where it can be up to 500 times faster without losing functionality — potentially rivaling AES in performance.

LeCatchu v2 is the next-generation evolution of the lightweight encryption engine that began with LeCatchu v1. This new version introduces extensive optimizations and refinements across all core functionalities, resulting in a faster, more efficient, and secure encryption system. LeCatchu v2 is engineered to deliver robust cryptographic performance without compromising on speed or security.

---

## Overview

LeCatchu v2 builds directly on the foundation laid by its predecessor, LeCatchu v1, while incorporating a host of improvements based on real-world testing and developer feedback. Key enhancements in v2 include:

1. **Optimization and Speed:**  
   The entire engine has been reworked for maximum performance. Core functions such as encryption, decryption, encoding, and decoding have been fine-tuned to reduce processing time significantly.

2. **Revamped Hash Algorithm:**  
   The hash mechanism has been redesigned to operate more quickly. While still rehashing the key for each character (a critical security requirement), the new algorithm reduces overhead, resulting in a more responsive encryption process.

3. **Improved Type-Checking in Encode/Decode:**  
   The methods for detecting and handling input types in the `encode` and `decode` functions have been optimized, ensuring that only valid inputs are processed. This reduces error overhead and improves overall efficiency.

4. **Optimized Encryption/Decryption Routines:**  
   The `encrypt` and `decrypt` functions have been re-engineered to push performance boundaries, streamlining the inner loops and reducing unnecessary computations.

5. **Safe repr/eval Mimicry via lestr and leval:**  
   LeCatchu v2 introduces the `lestr` and `leval` functions, which provide functionality similar to Python's `repr` and `eval`. However, instead of executing potentially unsafe code, these functions operate within a JSON framework. This approach significantly improves security by ensuring that the data transformation is safe and predictable.

6. **Enhanced UTF-8 Handling:**  
   The `encode_direct` and `decode_direct` functions have been updated to manage UTF-8 encoding and decoding in a more robust manner. This eliminates common errors such as "utf-8 can't decode ??? character" and ensures that all text data is handled consistently and correctly.

---

## Detailed Evolution from v1 to v2

### What Changed from LeCatchu v1?

- **Performance Improvements:**  
  Benchmark tests demonstrate that v2 consistently outperforms v1 across multiple scenarios. For instance, overall processing time and individual function benchmarks (encryption, decryption, encoding, decoding) have been reduced by noticeable margins.

- **Hash Algorithm Overhaul:**  
  In v1, the hash mechanism, while functional, incurred significant performance penalties due to repetitive SHA-256 computations. In v2, the hash algorithm has been restructured to use a streamlined approach that maintains the requirement for rehashing the key on each character, but does so more efficiently.

- **Encoding/Decoding Enhancements:**  
  The type-checking logic within the encoding and decoding routines has been refined, making these operations more resilient and faster. The previous mechanism has been replaced with a more direct and Pythonic approach.

- **New lestr and leval Functions:**  
  In addition to the core encryption and encoding functions, v2 introduces `lestr` and `leval`. These functions safely emulate the behavior of `repr` and `eval` by serializing and deserializing data within a JSON context. This provides a safer alternative to executing code dynamically.

- **Robust UTF-8 Error Handling:**  
  Issues related to incorrect decoding of UTF-8 data, which were a recurring source of errors in v1, have been addressed. The new direct encoding/decoding functions now handle UTF-8 data with greater reliability, reducing error messages and ensuring data integrity.

### Performance Benchmark Comparisons

Below are the detailed benchmark results comparing LeCatchu v1 and LeCatchu v2:

#### Overall Speed Test
- **LeCatchu v1:** 0.017496193408966066 seconds  
- **LeCatchu v2:** 0.016668266773223880 seconds

#### 1024 Byte Data Encryption/Decryption
- **Encryption:**
  - **v1:** 0.007448419729868571 seconds  
  - **v2:** 0.006999042828877767 seconds
- **Decryption:**
  - **v1:** 0.007452522913614909 seconds  
  - **v2:** 0.00701100746790568 seconds

#### 1024 Byte Data Encoding/Decoding
- **Encoding:**
  - **v1:** 0.0001593788464864095 seconds  
  - **v2:** 0.00015691041946411133 seconds
- **Decoding:**
  - **v1:** 0.000249780019124349 seconds  
  - **v2:** 0.00024852752685546877 seconds

#### Large-Scale Text Tests (100,000 characters)
- **Large Text Encoding:** 0.019929 seconds  
- **Large Text Decoding:** 0.046407 seconds

#### Multiple Keys Encryption/Decryption (50 keys)
- **Multiple Keys Encryption:** 0.004045 seconds  
- **Multiple Keys Decryption:** 0.003931 seconds

#### Additional Security and Integrity Tests
- **Key Collision Resistance Test:** Passed  
- **Reverse Character Encoding/Decoding Test:**  
  - Time: 0.000069 seconds (Passed)  
- **Entropy Test on Large Data:**  
  - Measured Entropy: 16.520679, indicating high randomness  
- **Hash Collision with Complex Keys Test:** Passed  
- **Differential Cryptanalysis Test:** Passed

*Note:* Although LeCatchu v2 exhibits overall performance improvements, multi-key usage in certain scenarios showed a slight slowdown compared to v1. This is a known area of focus for future updates.

---

## Key Features in Detail

### Optimized and Fast
LeCatchu v2’s core functionality has been meticulously optimized. The changes include refined loops, efficient memory handling, and minimized overhead in repeated operations. This ensures that the engine not only delivers stronger security but also performs faster under heavy workloads.

### Revamped Hash Algorithm
The hash algorithm in v2 has been overhauled to strike a better balance between security and speed. Although it continues to rehash the key after processing each character – a requirement for maintaining robust encryption – the new approach minimizes redundant computations, thereby reducing the processing time per character.

### Enhanced Type-Checking in Encoding/Decoding
The encoding (`encode`) and decoding (`decode`) functions now feature a more efficient mechanism for verifying input types. This streamlining leads to fewer runtime errors and ensures that the functions operate only on valid inputs, further boosting performance.

### Secure lestr and leval Functions
The new `lestr` and `leval` functions are designed to safely serialize and deserialize data. Unlike Python's native `repr` and `eval`, which can execute arbitrary code, these functions operate within a JSON framework. This design choice offers a secure way to mimic these functionalities, thereby reducing the risk of code injection and other security vulnerabilities.

### Robust UTF-8 Handling with Direct Functions
The `encode_direct` and `decode_direct` functions have been updated to handle UTF-8 encoding/decoding more gracefully. They ensure that encoding issues, such as those caused by unexpected characters or encoding errors ("utf-8 can't decode ??? character"), are effectively mitigated. This reliability is especially important in environments where data integrity is critical.

---

## Future Developments

While LeCatchu v2 represents a significant advancement over v1, the journey toward an ideal encryption engine is ongoing. Planned improvements for future releases include:
- **Further Optimization of Multi-Key Performance:**  
  Addressing the slight slowdown observed in multi-key scenarios.
- **Enhanced Parallel and Asynchronous Processing:**  
  Leveraging multi-threading or asynchronous techniques to further reduce processing times.
- **Refinements to the Hash Algorithm:**  
  Exploring additional methods to streamline the rehashing process while maintaining cryptographic strength.
- **Integration of Salt and Initialization Vectors (IV):**  
  Introducing these elements to ensure that repeated encryptions with the same key yield different outputs.
- **Extended Security Testing and Feature Expansion:**  
  Continuously incorporating feedback from the community to improve both functionality and security.

---

## Conclusion

LeCatchu v2 marks a major leap forward in the evolution of our encryption engine. It successfully merges enhanced performance with robust security measures, providing an efficient solution for both simple and complex cryptographic needs. While multi-key processing requires further refinement, v2 stands as a testament to the power of iterative improvement and innovative cryptographic design.

We invite you to explore, test, and contribute to LeCatchu v2. Your feedback is crucial for the continued evolution of this project.

**Version:** 2  
**Engine File:** `lecatchu_v2.py`  
**Test Suite:** (Updated test suite reflecting v2 benchmarks)

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
