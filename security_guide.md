### LeCatchu v8 (LehnCATH4) – Official Security Guide  
Butally honest, no hype.

This is the guide that should have shipped with v8 from day one.

LeCatchu v8 is now genuinely useful cryptography — but only when you treat it as a precision tool, not a magic black box.

The default settings are deliberately weak and fast, designed for demos and quick testing. They are not meant for real secrets.

Real security begins the moment you override those defaults.

Here is the unfiltered truth about every single parameter and what it actually does for (or against) your security.

encoding  
When turned off (which it is by default), the giant Unicode substitution table is never built. The engine starts in a few milliseconds and runs at maximum speed.  
When turned on, the engine spends seconds to minutes building a 3+ megabyte table that maps every possible Unicode character to a unique 3-byte sequence. This table adds exactly zero bits of proven security. For anything that actually matters, keep it off. Only use for encoding processes.

mostsecurity  
Only relevant when the substitution table is being built. It adds extra shuffling passes during table creation. The security benefit is negligible. The only real effect is doubling the startup time. It exists for people who enjoy watching progress bars.

special_exchange  
This is the most powerful security feature in the entire engine. It is a secret string (or byte sequence) that is silently appended to every single internal hash computation. Change one character and the entire cipher becomes a completely different, incompatible algorithm. This is real domain separation. This is per-application, per-device, or per-user isolation done right. The speed penalty is microscopic. Never, ever leave this empty in production.

xbase  
This controls how many rounds of hashing are performed when expanding short user passwords into gigantic internal numbers. Higher values create astronomically large internal keys and make accidental key collisions essentially impossible. It is not proper key stretching (it won’t seriously slow down a real attacker with GPUs), but it is cheap and effective at eliminating theoretical weaknesses. Values between 4 and 16 are the sweet spot. The original developer’s favorite is 9 — that gives roughly 693-digit internal numbers.

interval  
This is the classic speed-versus-security trade-off knob. At its safest setting (1), the keystream is refreshed after every single byte. Raising it repeats the same keystream bytes multiple times before refreshing. The higher you go, the faster the encryption becomes, and the lower the security margin gets. For anything under a few hundred megabytes, never touch this. For multi-gigabyte cold storage, small increases are acceptable.

IV / Nonce  
In the current version, the authenticated encryption path automatically generates and includes a long random nonce for every message. This is no longer optional in the safe functions — it is enforced. Without a fresh nonce, the same plaintext encrypted twice with the same key produces the same ciphertext, and the cipher collapses into the classic two-time pad disaster. Always use the authenticated paths. Never call the raw encryption primitives directly on real data.

TAC – Text Authentication Code  
In the latest version, the authentication tag is derived from the key itself, wrapped around the plaintext, and encrypted together with the message. On decryption it is automatically verified. Wrong key or tampered message → immediate rejection. This is no longer fake security theater. It is real authenticated encryption that actually works.

ivlength  
The default 256-byte random nonce gives a nonce space so large that birthday collisions are impossible before the heat death of the universe. 512 bytes is harmless overkill. Anything below 128 bytes starts becoming theoretically risky for extremely long-term use.

What LeCatchu v8 actually delivers today (2025) when used correctly  
- Instant engine startup  
- Full confidentiality and integrity  
- Unique cipher universe per special_exchange value  
- Automatic per-message randomness  
- Wrong-key and tampering detection  
- Zero external dependencies  
- Works on any Python 3.6+ installation in the world  

Safe to use for  
Personal file encryption, private messaging apps, offline note-taking, IoT firmware protection, long-term backups — basically anything that belongs to you and doesn’t have a legal requirement for certified cryptography.

Not safe (yet) for  
Banking backends, military communications, or anything where a nation-state or a compliance officer will come after you.

Final truth  
LeCatchu v8 is no longer a toy.  
It is now a real, lightweight, single-file, zero-dependency authenticated encryption system that actually protects data when used with discipline.

The security is entirely in your hands.

Use the safe path, set a strong special_exchange, keep interval at 1, never bypass the authenticated functions, and you’re good.

Use the lazy defaults and you’ll get exactly what you deserve.

Choose wisely.

– Simon Scap  
November 2025  
LehnCATH4 forever.
