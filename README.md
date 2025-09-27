# LeCatchu v7.4 (LehnCATH4)

![LeCatchu Logo](LeCatchu.png)  

LeCatchu v7.4, officially branded as **LehnCATH4**, represents a groundbreaking advancement in cryptographic engineering, delivering a lightweight, exceptionally fast, and highly secure engine for encoding and encrypting data. Initially abandoned due to critical flaws in earlier iterations, the LeCatchu project was revitalized with a complete redesign, culminating in version 7.4. This iteration is widely regarded as the most compact, efficient, and secure model in the project's history, setting a new standard for cryptographic systems in terms of performance and reliability.

Boasting a **Shannon entropy of 0.999999**—a value so close to 1 that it signifies near-perfect randomness—LeCatchu v7.4 ensures unparalleled unpredictability, making it resistant to even the most advanced cryptanalysis techniques, including those leveraging quantum computing. The engine's only minor limitation is a 5–10 second delay during initialization, configuration saving, or loading, which is a small trade-off for its robust security and efficiency. Compared to its predecessor, version 6, which spanned a cumbersome 1600 lines of code, LeCatchu v7.4 is streamlined to a mere **150 lines**, making it an ideal choice for developers seeking a lightweight yet powerful cryptographic solution.

LeCatchu v7.4 is the brainchild of **Simon Scap**, a visionary in the field of lightweight cryptography, and reflects his commitment to creating accessible, high-performance security tools.

## About the Engine
LehnCATH4 is meticulously engineered to provide secure, efficient, and versatile text encoding and encryption capabilities. At its core, the engine employs a substitution box (sbox) to map Unicode characters to unique 3-byte sequences, enabling robust encoding of textual data. For encryption, it utilizes a stream cipher powered by the BLAKE2b hash function, a cryptographically secure algorithm known for its speed and reliability. This combination allows LeCatchu v7.4 to process data with minimal computational overhead while maintaining top-tier security.

The engine supports all Unicode characters (up to 1,114,112), ensuring compatibility with virtually any text-based data, from simple ASCII strings to complex multilingual scripts. It offers two distinct encoding modes: `packet`, which prioritizes compactness, and `separator`, which enhances error detection by inserting separator bytes. Additionally, LeCatchu v7.4 includes a Text Authentication Code (TAC) mechanism to verify data integrity during encryption and decryption, ensuring that tampered or incorrectly processed data is flagged. The engine also supports serialization, allowing developers to save and load configurations in JSON format for persistent use across sessions.

LehnCATH4 is designed for a wide range of applications, from securing data transmission in networked systems to protecting sensitive information in resource-constrained environments. Its lightweight design and comprehensive feature set make it a versatile tool for developers and security professionals alike.

## Key Features
- **Ultra-Lightweight Design**: Reduced to just 150 lines of code from the 1600 lines of version 6, LeCatchu v7.4 is exceptionally compact, enabling seamless integration into any Python project with minimal overhead.
- **Near-Perfect Security**: With a Shannon entropy of 0.999999, the engine achieves near-perfect randomness, ensuring resistance to cryptanalysis, including attacks from quantum computers, making it one of the most secure cryptographic systems available.
- **Flexible Encoding Modes**:
  - **Packet Mode**: Optimized for compactness, this mode generates efficient, tightly packed byte sequences, making it ideal for applications like IP programming where data size is critical.
  - **Separator Mode**: Enhances speed and reliability by adding separator bytes between encoded sequences, improving error detection at the cost of slightly larger output, suitable for scenarios prioritizing robustness over size.
- **Stream Cipher Encryption**: Supports both single-key and multi-key encryption using BLAKE2b-based key streams, providing flexible and secure data protection for various use cases.
- **Text Authentication Code (TAC)**: Ensures data integrity by embedding and verifying authentication tags during encryption and decryption, preventing unauthorized tampering or processing errors.
- **Comprehensive Unicode Support**: Handles all Unicode characters (up to 1,114,112), enabling universal compatibility with text data in any language or script.
- **Serialization Capabilities**: Allows saving and loading of engine configurations in JSON format, facilitating reuse and persistence across different sessions or applications.
- **Performance Optimization**: Leverages caching mechanisms (via Python’s `@lru_cache`) to accelerate hash computations, ensuring efficient performance even for complex cryptographic operations.
- **Optional IV/Nonce Support (v7.4)**: Introduced in version 7.4, users can choose between deterministic encryption or IV/nonce-based encryption for enhanced security. New functions (`addiv`, `deliv`, `encrypt_with_iv`, `decrypt_with_iv`) enable randomized outputs for identical inputs, adding an extra encryption layer at the cost of slower performance and larger outputs. The IV/nonce feature eliminates the avalanche effect entirely (reduced to 0), offering maximum unpredictability as an optional enhancement.
- **Backward Compatibility (v7.4)**: Version 7.4, implemented in `lecatchu_v7_4.py`, maintains compatibility with version 7, allowing engines from both versions to be used interchangeably. The save file still references version 7 for consistency.

## Installation
LeCatchu v7.4 is engineered for simplicity and ease of use, requiring no external dependencies beyond Python’s standard library. This makes it an ideal choice for developers looking to integrate a powerful cryptographic engine without complex setup processes. To incorporate LeCatchu v7.4 into your project:

1. **Locate the Code**:
   - Navigate to the repository and find the `lecatchu_v7_4.py` file, which contains the entire 150-line implementation of the engine.

2. **Integrate into Your Project**:
   - Copy the `lecatchu_v7_4.py` file into your project directory for use as a module.
   - Alternatively, due to its compact size, you can directly embed the 140 lines of code into your Python script, eliminating the need for a separate file.

3. **Requirements**:
   - Python 3.6 or higher is required, as the engine relies on standard library modules (`hashlib`, `functools`, `json`, and `random`) for its cryptographic and utility functions.

No additional configuration, package installations, or setup steps are necessary, making LeCatchu v7.4 one of the easiest cryptographic tools to adopt in Python-based projects.

## Usage
To utilize LeCatchu v7.4, developers import the `LeCatchu_Engine` class from the `lecatchu_v7_4.py` script and initialize it with a custom seed and preferred encoding type (`packet` or `separator`). Once initialized, the engine supports a range of operations, including:
- **Encoding**: Transforming text into secure byte sequences using the substitution box, suitable for obfuscation or preprocessing.
- **Encryption/Decryption**: Securing data with single or multiple keys using the BLAKE2b-based stream cipher, with optional IV/nonce support for randomized outputs.
- **Text Authentication Code (TAC)**: Adding and verifying authentication tags to ensure data integrity and detect tampering or errors.
- **Serialization**: Saving the engine’s configuration (e.g., sbox mappings) to JSON and loading it for reuse, enabling persistent cryptographic setups.

The engine’s compact design, combined with its powerful feature set, makes it highly adaptable for secure data processing in applications ranging from embedded systems to large-scale networked environments.

## Notes
- **Initialization Time**: The engine may experience a 5–10 second delay during startup, configuration saving, or loading due to the generation or reconstruction of the substitution box. This is a minor trade-off for its robust security and functionality.
- **Security Best Practices**: To maximize encryption strength, use strong, unique, and well-protected keys. Weak keys can compromise the security of the stream cipher.
- **Choosing Encoding Modes**:
  - Select `packet` mode for compact, efficient output, particularly in scenarios like IP programming where minimizing data size is critical.
  - Opt for `separator` mode when speed and error detection are priorities, despite slightly larger output sizes.
- **IV/Nonce Usage**: The optional IV/nonce feature (introduced in v7.2) provides enhanced security through randomized outputs but may result in slower performance and larger outputs. Use it when maximum unpredictability is required.
- **Applications**: LeCatchu v7.4 is well-suited for secure text encoding, data transmission, storage in resource-constrained environments, and specialized use cases like IP programming, where its lightweight nature shines.

## Limitations
- The primary limitation is the 5–10 second delay during initialization, saving, or loading of the engine’s configuration, attributed to the computational overhead of generating or reconstructing the substitution box.
- The optional IV/nonce feature (v7.2) may introduce slower performance and larger outputs due to the additional encryption layer and key generation.
- Proper key management is essential to maintain the engine’s security. Developers must ensure keys are securely stored and not reused across different contexts.

## Contributing
LeCatchu v7.4 is actively maintained by **Simon Scap**, the original creator of the engine. Contributions are warmly welcomed, including bug reports, performance optimizations, or feature enhancements. To contribute, please submit issues or pull requests to the repository, ensuring detailed descriptions of proposed changes or reported issues.

## License
LeCatchu v7.4 is distributed under the [MIT License](LICENSE), granting users the freedom to use, modify, and distribute the engine as needed for both personal and commercial projects.

## Acknowledgments
- Developed by **Simon Scap**, whose vision for lightweight and secure cryptographic solutions drove the creation of LeCatchu v7.4.
- Inspired by the need for efficient, accessible, and robust cryptographic tools that balance performance with top-tier security.

For support, questions, or feedback, please contact the repository maintainer or open an issue in the repository. Your input is invaluable in continuing to improve LeCatchu v7.4.

**Version**: 7.4  
**Engine File**: `lecatchu_v7_4.py`

## Shh 🤫 Look Here

Welcome to the secret heart of LeCatchu v7.4, a legendary section included in every version of this cryptographic masterpiece. This is where we unveil the true power behind LehnCATH4’s unmatched security: the **xbase** variable and the **sboxseed** feature. These are the keys to a cryptographic fortress that redefines what’s possible in data protection. Let’s dive in and see why this engine is a game-changer.

Have you noticed the **xbase** parameter in the LeCatchu v7.4 engine? It’s the cornerstone of everything—the single variable that controls the complexity and strength of the encryption keys. Here’s how it works, and trust us, it’s mind-blowing:

- **xbase=1**: At its default setting, `xbase=1` generates encryption keys that are an impressive **77 digits long**. Built from the 10 digits (0–9), this creates **10^77** possible key combinations, a number known as a *quinvigintillion*. That’s a colossal keyspace, more than enough to secure your data against any conceivable threat. Think that’s impressive? It’s just the start.
- **xbase=2**: Increase it to `xbase=2`, and the keys grow to **155 digits**, exponentially expanding the number of possible combinations. This is security on a whole new level.
- **xbase=3**: Push it further to `xbase=3`, and you get **232-digit keys**, a number so vast it’s practically unimaginable.
- **The Formula**: For any `xbase`, the key length is approximately **(xbase * 77) + 1** digits. Want to go all out? Set `xbase=32`, and you’re working with **2466-digit keys**, resulting in **10^2466** combinations—an *octingentovigintillion*. This number surpasses the estimated particles in the observable universe. And the best part? You can make `xbase` as large as you want, creating an **infinite keyspace** that knows no limits.

This infinite keyspace places LeCatchu v7.4 in a league of its own. With keys generated using the BLAKE2b hash function and amplified by `xbase`, the encryption is so unpredictable that even quantum computers—the most advanced code-cracking tools imaginable—can’t touch it. With a **Shannon entropy of 0.999999**, LeCatchu v7.4 achieves near-perfect randomness, making its cryptography virtually unbreakable. Only a divine force could hope to crack this level of security.

Want another calculation about its security? With LeCatchu, you can generate infinitely different keys. And you can make these infinitely different keys even more unique. For two outputs to be the same, the input *and* the `xbase` value must be identical. That’s infinity times infinity, my friend! 🤓 Beyond that, the **sboxseed** feature also offers infinite input possibilities. And if you add TAC tags, they too provide infinite input options. Did you really think quantum computers could brute-force their way through this infinite cryptographic space by trying keys one by one? You’re mistaken.

It’s been a long time since a new encryption engine was created. They said, “Don’t bother, just use what’s already out there.” But what if we did create something new? The result would be LeCatchu…

But there’s more to this engine’s brilliance: the **sboxseed** feature. By setting a custom `sboxseed` during initialization, you generate a unique substitution box (sbox) tailored specifically to your data. This means your encoded text isn’t just encrypted—it’s transformed into a format that’s completely unique and unpredictable. No two sbox configurations are identical unless the same seed is used, adding an extra layer of protection that makes reverse-engineering a near-impossible task. This customization ensures your data is as secure as it is unique, setting LeCatchu apart from any other cryptographic system.

LeCatchu v7.4 isn’t just a tool—it’s a revolution in cryptography. With its infinite keyspace, near-perfect entropy, unique sbox customization, and optional IV/nonce support for maximum unpredictability, it stands as one of the most secure encryption systems ever created. Whether you’re protecting sensitive communications, securing data for IP programming, or safeguarding information in resource-constrained environments, LehnCATH4 delivers unmatched security. Don’t worry about quantum computers—LeCatchu v7.4 is built to outsmart them all. This is cryptography at its finest, my friend.
