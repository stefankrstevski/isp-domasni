# ISP Midterm 1 — Cryptography Implementation Cheat Sheet (WA1-WA4)

**Purpose:** decide what primitive an exam task requires, what key material and parameters it needs, which Java API to use, which bytes to send, how the receiver verifies/decrypts, and what security property is still missing.

**Based on this repository's homework** (secrecy, integrity, ae-pke, keyagreement, signatures) **and the two reconstructed historical practice protocols** in this directory. The theoretical meanings follow WA1-WA4. Some production guidance is added and explicitly identified.

## 0. Start here: choose the right primitive

| Task wording | Pick | The essential thought |
| --- | --- | --- |
| Encrypt a message when both parties already share a key | AES-GCM | Symmetric SecretKey + unique nonce; send nonce and ciphertext+tag |
| Just confidentiality, for CBC mode assignment | AES/CBC/PKCS5Padding | Shared AES key + unpredictable random IV; NO authentication |
| Just confidentiality, for CTR exercise | AES/CTR/NoPadding | Shared AES key + nonrepeating counter range; ciphertext malleable |
| Stream cipher exercise | ChaCha20 | Shared 256-bit key + nonce + initial counter; no integrity |
| Stream cipher with authentication | ChaCha20-Poly1305 | Shared key + unique nonce; includes an authentication tag |
| Check message integrity/authentication with a pre-shared key | HmacSHA256 | Shared MAC key; send message and tag; not encrypted |
| Compute fingerprint or hash chain | SHA-256 | No key, no IV; 32-byte digest; alone does NOT authenticate origin |
| Encrypt a small secret for someone with an RSA public key | RSA-OAEP | Recipient public key encrypts, recipient private key decrypts |
| Digitally sign a message | SHA256withRSA, RSASSA-PSS, SHA256withECDSA | Sign with sender private key; verify with trusted sender public key |
| Agree on a new shared secret | DH / ECDH | Both have their own ephemeral keypair; exchange PUBLIC keys |
| Derive an encryption key from low-entropy password | PBKDF2 | Password + salt + iteration count + output size |
| Derive separated traffic keys from ECDH material | HKDF | Extract then expand; context/info label, optional salt |
| Authenticate user with one-time hashes | Lamport hash chain | Store H^n(s), accept H^(n-1)(s), update stored value |
| Show why a cipher is weak | ECB, DES, RC4, CTR modification | Identify pattern leakage, small key, obsolete algorithm, malleability |

### Security properties — NOT interchangeable

- **Confidentiality:** hides plaintext. AES-CBC, CTR, ChaCha20, RSA-OAEP (correctly used) aim at this.
- **Integrity:** detects changes. HMAC, verified digital signatures, and AEAD tags provide this.
- **Authentication:** evidence of which *secret/key holder* produced a message. HMAC authenticates holders of a shared secret; a signature can authenticate a signer if the public key really belongs to that identity.
- **Authenticated encryption (AEAD):** secrecy + ciphertext integrity. AES-GCM and ChaCha20-Poly1305.
- **Forward secrecy:** later disclosure of a long-term authentication key does not reveal earlier ephemeral-DH session secrets, provided the old ephemeral secrets were erased and the exchange was authenticated.
- **Replay protection:** rejects a previously valid repeated message. HMAC, signatures and AES-GCM do NOT provide it alone. Add a session ID / sequence number / expiry and checked state. Lamport token consumption is a specific one-time mechanism.
- **Non-repudiation:** a properly validated digital signature can support it, given identity binding and key custody; MACs cannot distinguish which shared-key holder generated a tag.

## 1. Terms and Java objects in plain English

| Term | Meaning | Exam action |
| --- | --- | --- |
| Plaintext (PT) | Original bytes | message.getBytes(StandardCharsets.UTF_8) |
| Ciphertext (CT) | Encrypted output | cipher.doFinal(plaintext) |
| Symmetric key | Same shared secret for encryption and decryption | KeyGenerator, SecretKey, SecretKeySpec |
| Public/private keypair | Public part can be distributed, private part stays with owner | KeyPairGenerator, KeyPair |
| IV / nonce | Public per-message parameter | Generate/transmit it, pair with correct CT; ensure uniqueness or unpredictability as required |
| Salt | Public input to password key derivation | Generate a new random salt; send/store it with KDF parameters |
| Authentication tag | Proof that ciphertext or message was not modified under the key | MAC.doFinal or appended AEAD tag |
| Signature | Private-key proof over message bytes | Signature.initSign/private; Signature.initVerify/public |
| Digest/hash | Fixed-length output of a hash function | MessageDigest.getInstance("SHA-256") |
| ECDH shared secret | Equal byte sequence each side derives independently | KeyAgreement; never transmit this secret |
| Cipher transformation | Algorithm/mode/padding string | Cipher.getInstance("AES/GCM/NoPadding") |
| Key encoding | Byte representation of key | getPublic().getEncoded(), X509EncodedKeySpec |
| Key derivation | Convert secret material or password into cryptographic key(s) | PBKDF2 for passwords; HKDF for high-entropy ECDH material |
| PRG | Short seed -> pseudorandom long stream | Stream cipher concept |
| PRF | Keyed function that looks like a random function | HMAC conceptual model |
| PRP | Invertible keyed permutation looking random | AES conceptual model |

**Notation:** E : K x M -> C means encryption maps (key, message) to ciphertext. D : K x C -> M reverses it. "x" is Cartesian product, not vector multiplication. "||" means concatenate byte arrays; "xor" or the mathematical XOR symbol is bitwise exclusive OR.

### Common import map

~~~java
import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
~~~

## 2. General coding recipe for fri.isp Agent / Environment

Your existing homework uses the course message-queue simulator, not real TCP or TLS.

~~~java
final Environment env = new Environment();

env.add(new Agent("alice") {
    @Override public void task() throws Exception {
        send("bob", someByteArray);           // transport sends bytes
        byte[] response = receive("bob");    // blocks until a message arrives
        print("Got %s", new String(response, StandardCharsets.UTF_8));
    }
});
env.add(new Agent("bob") {
    @Override public void task() throws Exception {
        byte[] request = receive("alice");
        send("alice", "OK".getBytes(StandardCharsets.UTF_8));
    }
});
env.connect("alice", "bob");
env.start();
~~~

**Wire order is a contract.** If sender does send(nonce), send(ciphertext), receiver must do receive(nonce), receive(ciphertext). Mixing order gives authentication failures or hangs. Put independent stateful Cipher/Mac/Signature instances inside each agent, not one shared instance across threads.

**The most common Cipher lifecycle:**

~~~java
Cipher cipher = Cipher.getInstance("ALGORITHM/MODE/PADDING");
cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec); // when mode needs params
byte[] ct = cipher.doFinal(plaintext);

Cipher decrypt = Cipher.getInstance("ALGORITHM/MODE/PADDING");
decrypt.init(Cipher.DECRYPT_MODE, key, receivedParameterSpec);
byte[] pt = decrypt.doFinal(receivedCiphertext);
~~~

## 3. AES-CBC — secrecy only (secrecy/A1AESInCBCMode.java)

**Key:** ONE previously shared AES SecretKey. No RSA or EC keypair.

**Parameters:** random unpredictable 16-byte IV for each new message. The IV is **not secret**, and must accompany its ciphertext. AES always has 16-byte blocks, regardless of whether the key has 128, 192 or 256 bits.

**Java:**

~~~java
KeyGenerator generator = KeyGenerator.getInstance("AES");
generator.init(128);
SecretKey key = generator.generateKey();

// Alice
Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
encrypt.init(Cipher.ENCRYPT_MODE, key); // provider generates random IV
byte[] ciphertext = encrypt.doFinal(message.getBytes(StandardCharsets.UTF_8));
byte[] iv = encrypt.getIV();
send("bob", iv);
send("bob", ciphertext);

// Bob
byte[] receivedIv = receive("alice");
byte[] receivedCt = receive("alice");
Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(receivedIv));
byte[] plaintext = decrypt.doFinal(receivedCt);
~~~

**Provides:** message confidentiality under correct conditions. **Does NOT provide:** ciphertext integrity, authentication, replay protection. Tampering can create corrupted data and may facilitate padding-oracle attacks. The source homework sends ciphertext then IV; the above sends IV then ciphertext. Either is valid if both sides agree on the order.

## 4. AES-CTR — encryption with counter-generated keystream (secrecy/A2, A5)

**Key:** shared AES SecretKey. **Parameter:** 16-byte initial counter/IV; **the counter-block ranges used under the same key must never overlap**. The counter can be public. No padding.

~~~java
byte[] iv = new byte[16];       // illustrative ONLY: must ensure uniqueness
new SecureRandom().nextBytes(iv);
Cipher enc = Cipher.getInstance("AES/CTR/NoPadding");
enc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
byte[] ct = enc.doFinal(messageBytes);
// Send iv and ct. Receiver uses exact same initial counter.
Cipher dec = Cipher.getInstance("AES/CTR/NoPadding");
dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
byte[] pt = dec.doFinal(ct);
~~~

**IMPORTANT:** Random initialization is not sufficient by itself if high-volume use might overlap counter ranges. The homework uses controlled short ranges to keep Alice/Bob counter blocks separate.

**Provides:** confidentiality only. **Does NOT provide:** integrity/authentication/replay protection. CTR is malleable: if attacker XORs CT with a mask, the decrypted plaintext is XORed with that same mask. Your A5ActiveMITM.java uses this exact bit-flipping property.

## 5. AES-GCM — the default secure symmetric message choice (ae-pke/A1 and GCMExample)

**Key:** shared AES key, usually 128/256 bits. **Parameter:** unique nonce under this key, commonly 12 bytes, plus authentication tag of 128 bits. Reusing (key, nonce) is dangerous.

~~~java
SecretKey key = KeyGenerator.getInstance("AES").generateKey();
byte[] nonce = new byte[12];
new SecureRandom().nextBytes(nonce);

Cipher enc = Cipher.getInstance("AES/GCM/NoPadding");
enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
byte[] ciphertextAndTag = enc.doFinal(messageBytes);
// Send nonce, then ciphertextAndTag.

Cipher dec = Cipher.getInstance("AES/GCM/NoPadding");
dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, receivedNonce));
byte[] plaintext = dec.doFinal(receivedCiphertextAndTag);
// A tampered nonce/CT/tag or wrong key causes auth failure.
~~~

**Remember:** In Java, GCM Cipher.doFinal returns CT **with tag appended**. You do not need a separate HMAC. Nonce is public; send it. Verify the tag before using decrypted plaintext. For additional authenticated but not encrypted metadata, use cipher.updateAAD(metadata) on both sides before doFinal, with identical AAD bytes.

**Provides:** confidentiality, integrity and shared-key data-origin authentication. **Does NOT provide:** identity binding by itself, sequence-number replay protection, or secure key distribution.

## 6. ChaCha20 and ChaCha20-Poly1305 (secrecy/A3, ae-pke/A2)

### Plain ChaCha20

**Key:** shared 256-bit ChaCha20 key. **Parameter:** 12-byte nonce + 32-bit initial block counter. Keep the nonce/counter ranges unique under the same key.

~~~java
SecretKey key = KeyGenerator.getInstance("ChaCha20").generateKey();
byte[] nonce = new byte[12];
new SecureRandom().nextBytes(nonce);

Cipher enc = Cipher.getInstance("ChaCha20");
enc.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 0));
byte[] ct = enc.doFinal(messageBytes);
// Send nonce and ct; receiver uses same nonce AND counter (0).
~~~

Provides confidentiality; NO built-in integrity. Like CTR, ciphertext modifications cause predictable bit changes in plaintext.

### ChaCha20-Poly1305

**Key:** same 256-bit secret-key kind. **Parameter:** fresh unique 12-byte nonce. **Authentication:** built-in Poly1305 tag, appended to CT.

~~~java
Cipher enc = Cipher.getInstance("ChaCha20-Poly1305");
enc.init(Cipher.ENCRYPT_MODE, key); // provider generates nonce
byte[] ctAndTag = enc.doFinal(messageBytes);
byte[] nonce = enc.getIV();

Cipher dec = Cipher.getInstance("ChaCha20-Poly1305");
dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(nonce));
byte[] pt = dec.doFinal(ctAndTag);
~~~

Provides authenticated encryption; no automatic replay protection. Homework A2AgentCommunicationPublicSpace.java uses it to protect a SHA-256 digest in transit.

## 7. Hash SHA-256 (integrity/MessageDigestExample.java)

**Keypair?** None. **Symmetric secret?** None. **IV?** None. SHA-256 is *not encryption* and cannot be decrypted.

~~~java
byte[] digest = MessageDigest.getInstance("SHA-256").digest(messageBytes);
~~~

Output is **32 bytes = 256 bits**, regardless of input length. Same input -> same hash. A hash used alone is NOT an authenticity proof because an attacker can recompute the hash after modifying the message.

**Uses in homework:** file/message fingerprint, hash chains, hashing ECDH secret in historical task, SHA256(password || random challenge) in historical task. In production, prefer a dedicated KDF and a reviewed authentication protocol rather than using raw hashes to build one.

## 8. HMAC-SHA256 (integrity/A1 and HMACExample.java)

**Keypair?** None. **Key:** secret shared HmacSHA256 key. **IV?** None. **Send:** plaintext message + computed tag (32 bytes, if full SHA-256 tag).

~~~java
SecretKey key = KeyGenerator.getInstance("HmacSHA256").generateKey();

// Sender
Mac senderMac = Mac.getInstance("HmacSHA256");
senderMac.init(key);
byte[] tag = senderMac.doFinal(messageBytes);
send("bob", messageBytes);
send("bob", tag);

// Receiver
byte[] receivedMessage = receive("alice");
byte[] receivedTag = receive("alice");
Mac receiverMac = Mac.getInstance("HmacSHA256");
receiverMac.init(key);
byte[] expectedTag = receiverMac.doFinal(receivedMessage);
if (!MessageDigest.isEqual(expectedTag, receivedTag)) {
    throw new SecurityException("HMAC tag invalid!");
}
// ONLY NOW process receivedMessage
~~~

**Provides:** integrity and proof message came from someone with shared key. **Does NOT:** hide plaintext or prevent replay, and cannot prove which of two shared-key holders sent it. Never substitute plain SHA256(key || message) for HMAC.

## 9. PBKDF2 — from password to key (signatures/KeyDerivation.java; lock practice)

**Inputs:** password (char[]), salt (random public bytes), iteration count, requested key length. **Keypair?** None. **IV?** No (salt is not an IV). Output becomes secret key material for AES or HMAC.

~~~java
char[] password = "example-password".toCharArray();
byte[] salt = new byte[16];
new SecureRandom().nextBytes(salt);

PBEKeySpec spec = new PBEKeySpec(password, salt, 1000, 256);
SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
byte[] rawKey = factory.generateSecret(spec).getEncoded();
spec.clearPassword();

SecretKeySpec hmacKey = new SecretKeySpec(rawKey, "HmacSHA256");
// Or: new SecretKeySpec(rawKey, 0, 16, "AES") for a 128-bit AES key.
~~~

The **1000 iterations** above match the historical lock exam, not modern password-security recommendations; increase cost appropriately for production. The repository's older KeyDerivation.java uses PBKDF2WithHmacSHA1; the historical lock exercise requests PBKDF2WithHmacSHA256.

**Send/store:** salt and parameters; NOT password or derived secret. A salt prevents equal passwords from always deriving equal keys and defeats precomputed tables, but cannot make weak passwords unguessable.

**HKDF vs PBKDF2:** HKDF is for extracting/expanding relatively high-entropy key material (e.g. an ECDH shared secret); PBKDF2 deliberately slows guesses of low-entropy passwords. WA4 explains HKDF as extract-then-expand, but the existing homework does not include a standalone HKDF Java implementation.

## 10. RSA encryption with OAEP (ae-pke/A3, keyagreement/A1)

**Keypair?** Yes, RSA. **Sender uses:** recipient's PUBLIC key to encrypt. **Receiver uses:** own PRIVATE key to decrypt. **IV?** No external IV: OAEP uses internal randomized padding. **Send:** ciphertext, optionally authentic recipient public key or certificate beforehand.

~~~java
KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
rsa.initialize(2048);
KeyPair bobKeys = rsa.generateKeyPair();

Cipher enc = Cipher.getInstance("RSA/ECB/OAEPPadding");
enc.init(Cipher.ENCRYPT_MODE, bobKeys.getPublic());   // public encrypt
byte[] ct = enc.doFinal(shortSecretBytes);

Cipher dec = Cipher.getInstance("RSA/ECB/OAEPPadding");
dec.init(Cipher.DECRYPT_MODE, bobKeys.getPrivate()); // private decrypt
byte[] pt = dec.doFinal(ct);
~~~

**What RSA-OAEP does NOT provide:** sender authentication, replay protection, or forward secrecy for RSA key transport if the long-term private key is later stolen. It also cannot efficiently encrypt large data: encrypt a random AES key using RSA, then use AES-GCM for the actual data (hybrid encryption). For production explicitly configure modern OAEP digest/MGF1 options and use trusted public keys.

**Important naming trap:** "ECB" in RSA/ECB/OAEPPadding is a Java provider naming placeholder. RSA is not AES-ECB block-by-block encryption.

### RSA public-key bytes over the channel

~~~java
send("alice", bobKeys.getPublic().getEncoded()); // public is safe to reveal
byte[] encoded = receive("bob");
PublicKey bobPublic = KeyFactory.getInstance("RSA")
    .generatePublic(new X509EncodedKeySpec(encoded));
~~~

X509EncodedKeySpec reconstructs a PUBLIC key from bytes; it does NOT prove the key belongs to Bob! Trust/authentication of the key must be established separately.

## 11. Digital signatures — RSA, RSA-PSS and ECDSA (signatures/)

**Purpose:** sign a message and allow others to verify it. No encryption or shared AES key is implied.

**Key usage is the reverse of RSA encryption:** sender's PRIVATE key SIGNS, receiver uses sender's PUBLIC key to VERIFY. Private keys never cross the channel. **Send:** message + signature.

### RSA / SHA-256 signature

~~~java
KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
generator.initialize(2048);
KeyPair aliceKeys = generator.generateKeyPair();

Signature signer = Signature.getInstance("SHA256withRSA");
signer.initSign(aliceKeys.getPrivate());
signer.update(messageBytes);
byte[] sig = signer.sign();

Signature verifier = Signature.getInstance("SHA256withRSA");
verifier.initVerify(aliceKeys.getPublic());
verifier.update(receivedMessageBytes);
if (!verifier.verify(receivedSignature)) {
    throw new SecurityException("Signature invalid!");
}
~~~

RSA-PSS is another RSA signature scheme:
- Signature.getInstance("RSASSA-PSS")
- setParameter(new PSSParameterSpec("SHA-256","MGF1",MGF1ParameterSpec.SHA256,32,1))
- Sign/verify APIs are otherwise the same.
- The PSS salt is part of the **signature algorithm**, not a separately transmitted AES IV.

### ECDSA

~~~java
KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
generator.initialize(256); // coursework simplification
KeyPair aliceKeys = generator.generateKeyPair();

Signature signer = Signature.getInstance("SHA256withECDSA");
signer.initSign(aliceKeys.getPrivate());
signer.update(messageBytes);
byte[] sig = signer.sign();
// Receiver: Signature.getInstance("SHA256withECDSA"),
// initVerify(aliceKeys.getPublic()), update(received), verify(signature).
~~~

**Provides:** integrity and evidence of a private-key signer, if the public key is trusted. **Does NOT:** encrypt the message, create a shared secret, or reject a previously valid signed message on its own. RSA signatures and RSA-OAEP encryption are different operations with different roles.

## 12. DH / ECDH key agreement (keyagreement/ and both midterm practices)

**Problem solved:** Alice and Bob need the SAME shared secret without sending that secret.

- Alice generates (private a, public A).
- Bob generates (private b, public B).
- They exchange only PUBLIC A and B.
- Alice uses a + B; Bob uses b + A; both calculate the same shared secret.
- Use a KDF to get the AES session key; then AES-GCM to protect data.

**NO encryption Cipher is needed for the key-agreement calculation itself.** Use KeyAgreement. A Cipher comes *after* deriving the symmetric traffic key.

### ECDH Java implementation pattern

~~~java
// Each agent independently generates its OWN EC keypair.
KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
generator.initialize(new ECGenParameterSpec("secp256r1"));
KeyPair myEphemeralKeys = generator.generateKeyPair();
send("peer", myEphemeralKeys.getPublic().getEncoded());

// Receive the OTHER agent's public key.
byte[] peerEncoded = receive("peer");
PublicKey peerPublic = KeyFactory.getInstance("EC")
    .generatePublic(new X509EncodedKeySpec(peerEncoded));

// Combine MY PRIVATE key with THEIR PUBLIC key.
KeyAgreement ka = KeyAgreement.getInstance("ECDH");
ka.init(myEphemeralKeys.getPrivate());
ka.doPhase(peerPublic, true);
byte[] sharedSecret = ka.generateSecret();

// Coursework simplification: first 16 bytes -> AES-128.
// Preferred production approach: extract and expand with HKDF and context.
SecretKeySpec aesKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
~~~

**Source nuances:** The repo's ECDH/DH examples directly select the first 16 bytes of the secret. The 2023 historical assignment specifically says SHA-256(shared secret) then take first 16 bytes. These are different course constructions. Neither should be mistaken for a complete production KDF strategy.

### Classical DH

- KeyPairGenerator.getInstance("DH"), KeyFactory.getInstance("DH"), KeyAgreement.getInstance("DH").
- Work with DH parameters (large prime p and generator g) rather than EC curve parameters.
- Same conceptual steps: generate own key pair, send public key, combine own private + peer public, derive AES.

**What ECDH/DH does NOT solve:** MITM authentication. An active attacker can replace exchanged public keys. Sign the exchange or otherwise authenticate the peers. Generate fresh ephemeral DH keys and destroy them to support forward secrecy.

### Signed ECDH handshake (historical 2023)

1. Alice -> Server: A = Alice's ephemeral ECDH PUBLIC key.
2. Server: generate B and shared secret; sign A || B with long-term RSA PRIVATE key.
3. Server -> Alice: B, signature, fresh AES-GCM challenge nonce and encrypted challenge.
4. Alice: verify signature with pretrusted SERVER RSA PUBLIC key; compute shared secret and AES key; decrypt challenge.
5. Alice -> Server: fresh AES-GCM nonce and encrypted SHA256(password || challenge).
6. Server: decrypt proof, compare with expected, abort if invalid.

**Security mapping:** RSA signature -> authenticates server's handshake; ECDH -> shared secret; AES-GCM -> secrecy + integrity; password challenge -> authenticates Alice; ephemeral keys -> forward-secrecy potential.

## 13. Lamport SHA-256 one-time tokens (older midterm practice)

**Keypair?** None required for the lock itself. **IV?** None for the hash chain. **Secret:** Alice's random seed s. **Initial provisioning:** store H^1000(s) in the lock, authenticated via Server's password-derived HMAC.

~~~java
// H^n(s) = apply SHA-256 n times, NOT a numeric exponent.
static byte[] hash(int times, byte[] input) throws Exception {
    byte[] value = input.clone();
    for (int i = 0; i < times; i++) {
        value = MessageDigest.getInstance("SHA-256").digest(value);
    }
    return value;
}
~~~

**Setup:** Alice -> Server (via AES-GCM) H^1000(s); Server -> Lock sends anchor + salt + HMAC, using PBKDF2-derived HMAC key. Lock verifies HMAC BEFORE storing anchor.

**Use #1:** Alice sends H^999(s); Lock checks H(received) == H^1000(s), accepts and stores H^999(s).
**Use #2:** Alice sends H^998(s); Lock checks H(received) == H^999(s), accepts and stores H^998(s).
**Replay:** H^999(s) again will not satisfy the updated check, so reject.

**Provides:** one-time bearer-token verification and replay rejection *after successful consumption*. **Does NOT:** encrypt the NFC exchange or guarantee that an intercepted, not-yet-consumed token cannot be raced/used by an attacker.

## 14. Legacy / insecure primitives still present in your homework or theory

| Primitive | Key/block characteristics | Why it appears | Why it is insufficient |
| --- | --- | --- | --- |
| DES/ECB/PKCS5Padding | 64-bit block, 56 effective key bits | A4ExhaustiveSearch: teach brute-force key recovery | Tiny key space and ECB patterns; NEVER use for production |
| 3DES | 64-bit block, nominal 168 effective bits in 3-key form | WA1 theory | Legacy, slow, small block; avoid new deployments |
| RC4 | Stream cipher | SymmetricCipherExample.java | Obsolete; biased keystream, no authentication |
| Blowfish | 64-bit block | WA1 examples of historical PRPs | Legacy; not preferred for modern application encryption |
| AES/ECB | AES 128-bit block, no IV | WA1 semantic security demonstration | Identical blocks -> identical ciphertext blocks |
| One-time pad XOR | Truly random key as long as message | WA1 theoretical perfect secrecy | Key must be random, message-length and **never reused** |

**ECB distinguishing attack:** choose equal-length messages m0 = A || A and m1 = A || B, where A != B. Under ECB, output blocks equal => guess m0; unequal => guess m1. Success is perfect; no semantic security.

**CTR bit flip:** c = m XOR stream, c' = c XOR delta; then m' = m XOR delta. The A5ActiveMITM homework demonstrates this. Authenticated encryption detects such modifications.

**Brute-force DES:** A4 limits unknown DES bytes on purpose and tries candidate keys against known plaintext/ciphertext. This is not a recommended algorithm or key-management method.

## 15. What to send — fastest midterm reference

| Primitive | Sender transmits | Receiver needs locally |
| --- | --- | --- |
| AES-CBC | IV, CT | Same AES key; decrypt after IV received |
| AES-CTR | Initial counter/IV, CT | Same AES key; counter never overlaps under key |
| AES-GCM | Nonce, CT+tag | Same AES key; reject auth-tag failure |
| ChaCha20 | Nonce, CT | Same key, initial counter; **no integrity** |
| ChaCha20-Poly1305 | Nonce, CT+tag | Same key; reject failed tag |
| HMAC-SHA256 | Message, tag | Same HMAC key; verify tag first |
| SHA-256 digest | Digest (+ actual data separately) | Trusted comparison digest needed for meaningful integrity |
| RSA-OAEP | RSA ciphertext | Recipient's RSA private key; public key must be authentic |
| Digital signature | Message, signature | Trusted sender PUBLIC key |
| DH / ECDH | PUBLIC key bytes from each side | Own PRIVATE key, peer PUBLIC key, matching parameters |
| PBKDF2 | Salt and KDF parameters if required | Same password (never send it), algorithm/iterations/length |
| Lamport token | Next hash-chain token | Previously authenticated stored chain value |

### Common parameter sizes

- AES block size = 16 bytes = 128 bits. AES keys = 16/24/32 bytes.
- CBC IV = 16 bytes; fresh and unpredictable.
- CTR initial block = 16 bytes; unique nonoverlapping counter space.
- GCM common nonce = 12 bytes; common tag = 128 bits = 16 bytes. Always ensure uniqueness per key.
- ChaCha20/ChaCha20-Poly1305 key = 32 bytes, nonce = 12 bytes; plain ChaCha20 also requires initial block counter.
- SHA-256 digest and HMAC-SHA256 full tag = 32 bytes.
- RSA sample key size = 2048 bits. EC sample curve = secp256r1 (P-256).
- PBEKeySpec key length is in **bits**, e.g. 256. GCMParameterSpec(128, nonce) uses **tag bits**.

## 16. Midterm traps / questions to defend

1. **Do I need a keypair?** Only for public-key encryption/signature/key agreement. AES/HMAC have shared secret keys; hash has no key.
2. **Which part of the keypair?** RSA-OAEP: recipient public encrypts, recipient private decrypts. Signatures: signer private signs, verifier trusted public verifies. ECDH: own private + other public calculate secret.
3. **Does an RSA public key from the network prove Bob's identity?** No. It must be authenticated separately.
4. **Is SHA-256 encryption?** No. It is one-way hashing, no key and no decryption.
5. **Is HMAC encryption?** No. It checks integrity and secret-key possession but leaves plaintext visible.
6. **Does AES-GCM need HMAC?** No. GCM already authenticates ciphertext and optional AAD.
7. **Do I send IV/nonce/salt?** Yes, where needed. They are public parameters. Never send the secret AES key, password or RSA private key.
8. **Does AES-CTR have padding?** No. CTR acts like a stream cipher.
9. **Why is ECB insecure?** Deterministic block processing leaks repeated plaintext patterns.
10. **Does successful AES-CBC decryption prove integrity?** No. CBC has no authentication tag.
11. **Can I reuse GCM nonces?** No, never under the same key. Likewise avoid CTR counter reuse.
12. **Does ECDH authenticate Bob?** No. Add trusted digital signature or established authentication.
13. **Is a digital signature confidential?** No. Anyone can read the signed plaintext unless separately encrypted.
14. **Does AES-GCM stop replay?** No. Valid old ciphertext can still verify; add sequence IDs/freshness checks.
15. **When to choose PBKDF2 vs HKDF?** Password -> PBKDF2; ECDH/high-entropy material -> HKDF.
16. **What goes over the wire after ECDH?** Public keys and then protected messages; NEVER the shared secret.
17. **Does a Lamport token need public-key crypto at the Lock?** No; it only hashes and compares.
18. **Why must MAC/signature verification precede processing?** Untrusted data must not be accepted as authentic before verification.

## 17. How to study from your actual files

- **WA1 / secrecy:** SymmetricCipherExample, A1AESInCBCMode, A2AESInCTRMode, A3ChaCha20, A4ExhaustiveSearch, A5ActiveMITM.
- **WA2 / integrity:** MessageDigestExample, HMACExample, A1AgentCommunicationHMAC.
- **WA3 / authenticated + public-key encryption:** GCMExample, A1AgentCommunicationGCM, A2AgentCommunicationPublicSpace (ChaCha20-Poly1305 + authenticated digest), A3AgentCommunicationRSA, RSAExample.
- **WA4 / exchange + signature + derivation:** A1AgentCommunicationKeyExchange (RSA-wrapped AES key), AgentCommunicationDH, AgentCommunicationECDH, SignatureExampleRSA, SignatureExampleRSAPSS, A2AgentCommunicationSignature, KeyDerivation.
- **Integrated historical exam simulations:** Practice_OneSidedAuthenticatedKeyExchange01 and Practice_LamportElectronicLock02.

**Recommended study pattern for every file:** (1) underline key/material generation; (2) circle Cipher/Mac/Signature/KeyAgreement configuration; (3) write down send/receive order; (4) identify key usage; (5) state which security goals are fulfilled and which remain missing; (6) explain how a tampered or replayed message would behave.

**Production caveat:** The homework and historical midterms intentionally use some outdated/educational choices. For real systems, favor TLS 1.3 and reviewed AEAD protocols, authenticated ephemeral ECDH with HKDF, appropriate password-hardening cost, nonce management, and tested replay controls.
