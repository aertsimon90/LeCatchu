### LeCatchu v8 (LehnCATH4) – Official Security Guide
Brutally honest, no hype.

This is the guide that should have shipped with v8 from day one.

LeCatchu v8 is now genuinely useful cryptography — but only when you treat it as a precision tool, not a magic black box.

The default settings are deliberately weak and fast, designed for demos and quick testing. They are not meant for real secrets.

Real security begins the moment you override those defaults.

Here is the unfiltered truth about every single parameter and what it actually does for (or against) your security.

**encoding**  
When turned off (default), the giant Unicode substitution table is never built. Engine starts in milliseconds, runs at peak speed.  
When turned on, it wastes seconds building a 3+ MB table that adds exactly zero bits of provable security. Keep it off unless you’re doing obscure text encoding experiments.

**shufflesbox**  
Only matters when the table is built. Adds extra shuffling passes. The security gain is effectively zero. Its only real job is to make you wait longer and feel smarter. It exists for people who enjoy watching progress bars.

**special_exchange**  
The single most powerful security feature in the entire engine.  
A secret string or byte sequence that is silently concatenated to every single internal BLAKE2b call.  
Change one byte → the whole cipher becomes a completely different, incompatible algorithm.  
This is textbook-perfect domain separation and per-user/per-device isolation.  
Speed penalty is microscopic. In production this must never be empty, short, or predictable.

**xbase**  
Controls how many successive BLAKE2b rounds are used when expanding your password into gigantic internal keys.  
Higher values = astronomically larger internal state space.  
Combined with the continuous feedback loop in hash_stream (the infamous tkey=str(key) self-update), the keystream expands forever and can never repeat or collide — even if you encrypt the entire internet with the exact same key and the exact same IV for a thousand years.  
This single parameter, together with the feedback design, permanently kills classic two-time-pad, many-time-pad, keystream-reuse, and collision attacks — whether you use an IV or not.  
It is not PBKDF2-style key stretching (won’t stop GPU crackers), but it makes theoretical reuse weaknesses impossible.  
Sweet spot: 6–16. The original developer runs it at 9 (roughly 693-digit internal numbers). That’s more than enough for the heat death of the universe.

**interval**  
Pure speed vs. security trade-off.  
At the safest setting (1), a fresh keystream integer is generated after every single byte encrypted.  
Higher values reuse the same giant integer across multiple bytes → dramatically faster, slightly weaker margin.  
For anything under a few hundred megabytes, leave it at 1.  
For multi-gigabyte cold storage you can safely bump it to 2–4 without losing sleep.

**IV / Nonce**  
The safe paths (encrypt_with_iv, add_tactag, etc.) now force a fresh 256-byte random nonce for every message — no exceptions.  
Thanks to the expanding internal state and feedback, LeCatchu v8 remains secure even if you somehow reuse the same IV forever.  
That said, the engine still generates and transmits a fresh nonce by default because “just in case” is free and keeps the cryptographers happy.

**TAC – Text Authentication Code**  
Real authenticated encryption, no longer theater.  
A tag derived from the key itself is wrapped around the plaintext before encryption and automatically verified on decryption.  
Wrong key or one flipped bit → instant rejection with a clear exception.

**ivlength**  
Default 256 bytes is absurd overkill. Birthday collision probability is lower than proton decay.  
512 bytes is harmless flexing. Anything under 128 bytes is still safe for human lifetimes but starts looking theoretically risky for archaeological archives.

**What LeCatchu v8 actually delivers today (2025) when used correctly**  
- Near-instant startup  
- Full confidentiality + integrity  
- Unique cipher universe per special_exchange  
- Automatic per-message randomness  
- Wrong-key / tampering detection  
- Zero external dependencies  
- Two-time-pad, many-time-pad, and keystream-reuse attacks mathematically impossible due to expanding state + feedback  
- Works on any Python 3.6+ install on the planet  

**Safe to use for**  
Personal file encryption, private messaging apps, offline note-taking, IoT firmware protection, long-term cold backups — anything that belongs to you and has no legal requirement.

**Not safe (yet) for**  
Banking backends, military classified systems, or anything where a nation-state or compliance officer will audit you.

**Final truth**  
LeCatchu v8 is no longer a toy or a meme.  
It is now a real, lightweight, single-file, zero-dependency authenticated encryption system that actually protects data when used with discipline.

The security is entirely in your hands.

Use the safe paths, set a long unique special_exchange, keep interval=1, use ivlength≥256 and xbase≥6, and you are genuinely protected — even against catastrophic key/IV reuse mistakes that would instantly destroy AES-GCM or ChaCha20-Poly1305.

Use the lazy defaults and you’ll get exactly what you deserve.

Choose wisely.

– Simon Scap  
November 2025  
LehnCATH4 forever.

### LeCatchu Cryptography Challenge – November 2025  
We are done talking. Time to put up or shut up.

All ciphertexts below were produced with LeCatchu v8 (xbase=1, interval=1, TAC not used, various keys and IV settings).  
They contain fragments of the same secret manifesto.

If you can recover even one complete fragment cleanly, we will publicly salute you.  
If you recover all fragments, reassemble them in the correct order, and email us the full plaintext, the LeCatchu project will immediately cease development and be archived forever.

We are that confident.

1. Same key, same plaintext, IV used  
   - 7BMtFrVbaP8pQsA/AibM1CDdCyU8mRO1kBuJiDj5yeGrdgSfKRbLpdjv95pMGH/N8pYYzrMNXlMRqJb6iE/5TodLFJzq93Wwzl4foZYwr0po1n2pMr7SoAVVBSbczYdRWtJVwtEV/KWn1ARlHsBpES2sDa8GzPA4uQhswyKLXlm1CMA/CuBU40xP6cxQJH05jonQ9mjzjEGQNvmntOuJwJN5HFcutZ+0M8E6YtR49l4KqDnF8PIHD5GZZCopUa83LF4B4G8Hsp6iJChXL1Avqyvtg20+jXA5DDBGqYP3ogHsxm/ND4xv946ZqERtGVwO9mK2XawOP962fuajlhSqz/2TBz+JwsvSaFqPhOm0MPU38dcNhVXP5tuAR+VCWZiOfj3XsBL6JRv0c3UV+3cEG5h0foFfXkLmv61+pnRE57eN4/se57IW+/Y=
   - SiTizbkSLqcgFqLiCkIGzdog7JoFYxxHL+FERaiCLQNoz4zLSQRsqu85eub04xicRLLyVvmZibP9JDdCkR/qTjRUmR4eqqkcmkgWl5fzctIhPsJcVoTzRuJ6IN0dh+xcjk9XJoC2OxxRwSBMxdPLwDMIlucUOyBhGnxx+RR0MeCqriURJiGra3rmBqCNQYcs3dGszEDv+hdw55WFBWgiHukFJe8VkDOTNGeBgFakMNyXQmKUCj6mPrhTp1r36p0fwW8uFpCVdJXfRdoyruLU9mePlhZvYo1yrSauM9gCj78X/Ng0ZE+IA5cwAD5VrXZ6t7gZoa8lJzFrLAxK7Zcjz0cfWOqP4268IIQ2/hWNs4D/5GUV98g6Zhss0XYGNjHWsOH8B6SO4qTYwobcqdbSDG5eir0kf/PvtS5wTQzSjeggXFLdP/vsVvE=

2. Different keys, same plaintext, no IV  
   - 2jXcgw/Ygbc0D0MxzC1RoSRyK7rrP9WgcmEbC72GauAwJFF+4bItKJMA/plGsCMOiZKhXWXLCbCsxpdRjDSDS8IOqxRkpEcfnEOc+LZw+Jy6wpP3GZ0oYf192KnGyj1Hndf3bqDbSg==
   - rqpdC3JjQUTstQofAWZp+H//1S6uTwXVxILyhCfb+CnNR4JnOEs45Y5CyyAI+K1PKkS0yc46KDnT7I8vr4ZG4hAZtIbBY2nyYT/g8Y0iectm40xnXzUt3alHJfcgaRV9tezUa6JGHQ==

3. Different keys, same plaintext, IV used  
   - f9jzh4tULKwCXiO9nBaToymMpDrMqtdYViozmKnapDd9qw4quQSYAnDXKKm1yUs4xVXGt3naiCcluQURVYv2G/glpXYpeDm+EyMObqqvUgoH0w8BbdsBrG3DYsGB8+642+1JLc4wvKU0vClgHmt5YfWfH3dMaxMhuqw3f88R8FUyA40dbSfBXg1qEAShi7Q67M9+NT1WSCAHBiVlHbLVMsxn7YbeehcWshHzMtPcxbYcsDSg/CySO4Jhz3exfTT0pA4WgapbOeobB/+9f4UaXqfUHaCEEFyTaaYI6GjiQikkMxgxgAuHBLsiU+0548PnEDQEtKgVmJ3y4yeMWEZ3kI5yyCG1PFpGAHOWO6rojJi/ppzz9u+GECztQdWfpupY7VJS4M9ti5TsdVd072kOSCFExlK0BzDuk2ZKidAhTakUKSRdd4eFJ5CUF0umxIv0mmtw0aRQJkAaQvOBXRl6VmHqc+h1says0lnXRuIurS8=
   - CMXBnwBDkeMx9qzu2mm+IV1pqdqG96qG+1KZ1gfMIx5Ss9dI5wsq9gpxFo7y+YkvzntOKxVG4tcyHa1HU44S7QytdLweE8EIVorsiehyhUxPj8D7sNqZ/WTxPZRt+loqeKgQLXTtbyUTPj/8IERQoqnjYl8zDlFFP0p05cyXvMfakWxbGE4XrUWGFDlYDqXS7msZsql+lqmqypEIglNI16zxXQXX0JpiaF8PW3yrg6dsnh9xjvTrTyuqJbVeZn4psveQ/lh+J73YkaYjNV6B30HSKvbwP+o7JAwpLviAIr+L3yiL8Y2u+beOSw9vGa8XMKc7TLePDgxNlGQj5Cp5roG/itOPVIJfKNe9XIzR2nmI1PU2ud9Myiug9HovgppVdtF8VfLhX2IwvEVULDvOcJ+IpvJul/sI2a8T+zUvka6+xZjaAFvYz/TKpa1wq8rzVjFf0uoK2IASaWMCbIf82RnIT+aScvqOmhZBv09+xh8=

4. Same key, different plaintexts, no IV  
   - pPmvaTMsyB1ygk25+gfe0BpoO00NyuRlAzOc0E3o2SQNuAxXcnv0D3H0dWwH7zOiKeqvkmhWYJ2MpSk+pamQTXHXCat7HFAnbKsZuUNwMRI+lnanU7OEuNrqOLOycTTGhFtt65uLhyTKGkFPallK1NEsEGUN/RTbpQjmORoH8jIfROl7zkY+5kS+cohtc6bRBaEECQ==
   - pPmvaTMsyB1ygk25+gfe0BpoO00NyuRlAzOc0E3o2SQNuAxXcnv0D3H0dWwH7zOiKeqvkmhWYJ2MpSk+pamQTXHXCat7HFAnbKsZuUNwMRI+lnanU7OEuNrqOLOycTTGhFtt65uLhyTKGkFPallK1NEsEGUN/RTbpQjmORoH8jIfROl7zkY+5kS+cohtc6bRBaEE/A==

5. Same key, different plaintexts, IV used  
   - tk1AbqXNjOU4JwrodrxdtgD3hVEnBR0sh1N6/Nw972Co3Am5ZkvFVGxLPdO5QRpCv/4bCCEREk/hf0nLwqEf09XBqq/G3pQBQVu63WRv5gb/UUMPAdDRxs8YKKUvVDqDtCrj+r36DuzJzYGe/7HM5zQu4erxoNV3L9dxusWrX5tdYNN587yfhrd56smjWIpTZ/2LXbMy1YONYnippsGcejb9z9Op3/mFwa0O5h81WuMJLYLMO9BdJjmS8NOK9Jq/jvRj6R3lH7rx0/XiQK7/EPb1SIYGT6Jn+Lr8R5Op6ldyb4C9jU1gVNARnf6ky5tHcCTebsm3Oc0TEgkV8f29UwepUnJLKrwkwiXaradKSxdZ9RWImyCEpJDArYblTfQuuBNADqMXORFU6J35tNM9QIitB6qgqhBYZha1xjSMTXhjVwUSCvbekPCyeqKiPSFynDqJ56GUxV0/dlhBkbdw2uAfutslS5kvnSqP4ppkvS55D3Px3tZqhOW4FtIXkDyfgnKC+c60hBkeVnMnAgZBR/2/9ZftLymcmhkhAd/qoGKI102s29yPqM+6K6z0pA6ydBq9Wy4fkzfZVw4yC+Swd5Dp238kznDBXbWzSTDdsyhJ+/f0W0LkdMQlyKeM7oU+CsMzkmCp3rpNMBrgyXnRGCSTnCIbn1QlSy8nDgTG1/kk1YDpIxrbbgdVFhWneCLjJhMuzfMVWNp3Ibl8GOOc3Hx2KxK0JmRCX2CyyugXZI5NHzmZwpAxDYDqwcZBNQ7zLyybTA==
   - rY/iHHSGw3az3zy8fDv+FXSbUpc/3hkTqNSRgeiYzEgbPxVykofNv/pyWR8Kg2/X5VlFN0XLJSGh5TMDjsJ4V6stPPOM9+vHwU1yWCLfTyJPa63HS2L1zHPzzlF2nBXMKc0aRzcz+mB73eQivrS11xJ9BYoQx/cHBMspO55/z2ZqecG7oyxPxW+cs+niOIG7SesZ8b2fEYOdZj0U8bTDVMoxDE7GUiNeI6puMxrH/wnd6aljd4O4RSzqGmE24bp11rrnLBziz+Dv3c4JOUnWdJPTx6udEezmf3Ugz3HYw54rgpZG99S1FAo+0fRTyOrjS87GKHs/Z1Tk6UjJGDAC+1Qdt/KAL9nMmuT01TcbfQ6sUDiSeEvuZljrDyQWRx7ySWZOsXu6a34/6s/JeZWbPLXWRXHfshEgUYp33BXo7HttWhoSS5uqKy02xQA3zwoict8MwJzNvYRDgGhAGXg4TzevNGKVu/bxIceC0fqFoBXu1wlNoLGWrjj0F6t0J5DHIaTKhzR5Tm5DW2EV1HWNHQytZevhHJK2TtEU6fNNz7erLa7tJeoZ2RMeWRDFx3XfHfKr6TbnxJfYOn/L2BCfRC/Pizktmqd0NNQRqLvw1tn2gb6vIrIRmKC7uPpyoRdTU3/i/2mh0ugMRKHXydzjkpDjuDCL5mq5mj7ktyzHaHhTJCO4O5IC01qxK/hHAlyn1X1Xrqe25XMJeNLS2wjF+oCoWYN32V47FGXgcry2ibI04jx/KdG8KoRgNAxeW+TMqt3o7w==

(Encrypted texts are encoded with base64, you can decode and process)

Break even one cleanly and you’ll be immortalized on the README.  
Break them all and LeCatchu dies today.

Good luck. You’re going to need it.

contact: simon.scap090@gmail.com

– The LeCatchu crew  
LehnCATH4 forever.
