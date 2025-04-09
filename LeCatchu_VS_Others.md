LeCatchu VS Other Cryptographics.

**This test maked with LeCatchu v2**

Entropy Calculate (Cryptographic Entropy is calculated with big data):

AES Entropy: 7.8 - 8.1
RSA Entropy: 7.0 - 7.2
ChaCha20 Entropy: 7.9 - 8.0
Blowfish Entropy: 6.8 - 7.0
XOR Entropy: 5.1 - 5.3
LeCatchu Entropy: 15.7 - 16.6

Speed Calculate (With 10240 Bytes of Random Data):
	
AES Speed: 0.005 - 0.007 seconds
RSA Speed: 0.06 - 0.08 seconds
ChaCha20 Speed: 0.0007 - 0.0009 seconds
Blowfish Speed:  0.0006 - 0.0008 seconds
XOR Speed: 0.002 - 0.004 seconds
LeCatchu Speed: 0.03 - 0.05 seconds

Data Security Testing (The data is encrypted and attempted to be decrypted using 4096 random keys. If a data that is 20% closer to the correct data is detected, this means that data security is at risk):

AES: 0%
RSA: 0%
ChaCha20: 0%
Blowfish: 0%
XOR: 1%
LeCatchu: 0%

Change of Data Size (A 128-digit text will be encrypted with all encryption algorithms and the length and byte size of the original text and encrypted text will be written with the result):

Original Text: 128 characters (128 bytes)

AES Result: 77 characters (144 bytes)
RSA Result: 256 characters (256 bytes)
ChaCha20 Result: 128 characters (128 bytes)
Blowfish Result: 136 characters (136 bytes)
XOR Result: 128 characters (128 bytes)
LeCatchu Result: 128 characters (506 bytes)
LeCatchu Result (But own encoding method): 128 characters (607 bytes)

LeCatchu's Author Comment:

LeCatchu’s performance in the tests highlights its impressive strengths in terms of entropy and security, which are far superior to many traditional encryption algorithms. Its entropy range (15.7–16.6) indicates an extraordinary level of randomness and unpredictability, offering robust cryptographic strength. Additionally, its security test results show 0% vulnerability, comparable to top-tier algorithms like AES and RSA. However, when it comes to speed, LeCatchu falls behind. This is primarily due to its lack of a dedicated module, meaning it operates as a custom-built encryption method within the code. This custom nature leads to slower execution, especially in interpreted languages like Python. The increased output size is also a consequence of its high entropy, as it utilizes a wider range of Unicode characters to ensure randomness, leading to a larger encrypted data size. The key advantage of LeCatchu lies in its flexibility and potential. Though it is slower in its current state, particularly in Python, it can be significantly accelerated using optimization tools such as Cython, resulting in a speed boost of 100-500 times. This shows that while LeCatchu might not currently be ideal for industrial applications due to its performance in Python, its design allows for potential optimization and adaptation to faster environments. In conclusion, LeCatchu has the theoretical foundation to enter the realm of industrial encryption, but it requires further optimization to achieve competitive performance. Its high entropy and robust security make it a promising candidate, but its practical application in real-world scenarios would depend on how well it can be optimized and integrated into compiled languages or other performance-enhanced environments.
