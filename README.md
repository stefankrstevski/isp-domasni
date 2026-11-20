# ISP labs: crypto cheat sheet

Java examples of secrecy, integrity, authenticated encryption, key exchange, and
signatures. Each class runs through its own `main()`. Most exercises are implemented;
[A4ExhaustiveSearch](./secrecy/A4ExhaustiveSearch.java) still has TODOs, and
[A5ActiveMITM](./secrecy/A5ActiveMITM.java) still forwards ciphertext unchanged.

## Code map and key APIs

| Area | Start here | What to understand |
| --- | --- | --- |
| [Secrecy](./secrecy/) | [AgentCommunication](./secrecy/AgentCommunication.java), [SymmetricCipherExample](./secrecy/SymmetricCipherExample.java) | Agent messaging and the encryption lifecycle. CBC, CTR, and ChaCha20 exercises each exchange ten requests and ten replies. |
| [Integrity](./integrity/) | [MessageDigestExample](./integrity/MessageDigestExample.java), [HMAC exchange](./integrity/A1AgentCommunicationHMAC.java) | Hashing versus secret-key authentication; verify before using a message. |
| [Authenticated / public-key encryption](./ae-pke/) | [GCMExample](./ae-pke/GCMExample.java), [RSA exchange](./ae-pke/A3AgentCommunicationRSA.java) | Encrypt and authenticate with GCM; encrypt to a recipient's public key with RSA. |
| [Key agreement](./keyagreement/) | [RSA key transport](./keyagreement/A1AgentCommunicationKeyExchange.java), [DH](./keyagreement/AgentCommunicationDH.java), [ECDH](./keyagreement/AgentCommunicationECDH.java) | Establish a shared secret, then encrypt the message with AES-GCM. |
| [Signatures / key derivation](./signatures/) | [ECDSA exchange](./signatures/A2AgentCommunicationSignature.java), [KeyDerivation](./signatures/KeyDerivation.java) | Private keys sign, public keys verify; derive a key from a password. |

**Security goals:** confidentiality hides content; integrity detects changes;
authentication establishes the source; replay protection rejects old valid messages.
One does not automatically provide the others.

- `Environment` connects agents; each `Agent.task()` runs concurrently.
  `send("bob", bytes)` sends bytes; `receive("alice")` blocks until bytes arrive.
  These are simulated queue channels, not Internet sockets or TLS.
- `env.connect(...)` links peers; `env.mitm(...)` inserts the attacker in
  [A5](./secrecy/A5ActiveMITM.java). Keys captured from `main()` model secrets
  already shared securely; that setup does not solve key distribution.
- `Cipher`: `getInstance(algorithm/mode/padding)` -> `init(...)` -> `doFinal(bytes)`.
  `KeyGenerator` makes symmetric keys; `KeyPairGenerator` makes public/private pairs.
  `Mac` creates tags; `Signature` signs/verifies; `KeyAgreement` computes shared secrets.
- Give each agent its own stateful crypto objects. Convert text with UTF-8 and log
  ciphertext with `Agent.hex(...)`, not `new String(ciphertext)`.
- `X509EncodedKeySpec` + `KeyFactory` reconstruct public keys from bytes.
  **X.509 key encoding is not a certificate or proof of identity.**

## Algorithms and protocols: why use them, what is missing?

Most names below are algorithms or modes. The agent exchanges build small teaching
protocols from them, rather than implementing a complete production protocol.

### Encryption

| Used here | Why useful | Limitation and how it is handled |
| --- | --- | --- |
| RC4 | Simple stream-cipher API demo. | Obsolete, biased keystream, no authentication. [Intro example](./secrecy/SymmetricCipherExample.java) only; use modern authenticated encryption in applications. |
| DES / ECB | Demonstrates brute force and poor key selection. | DES has only 56 effective key bits; ECB reveals repeated-block patterns. [A4](./secrecy/A4ExhaustiveSearch.java) further restricts the key. Use AES with authenticated encryption outside this exercise. |
| AES-CBC / PKCS5Padding | XOR each plaintext block with the previous ciphertext block before encryption; the first uses the IV. Padding handles partial blocks. | Needs a fresh unpredictable 16-byte IV; no integrity, with tampering/padding-oracle risks. [A1](./secrecy/A1AESInCBCMode.java) generates IVs through the provider, but still needs authentication. Prefer AEAD, or carefully designed encrypt-then-MAC with separate keys. |
| AES-CTR / NoPadding | Encrypt counters to generate a keystream, then XOR with plaintext. Fast; no padding. | Never repeat a counter block under a key; attackers can flip plaintext bits. [A2](./secrecy/A2AESInCTRMode.java) separates counter ranges, but does not authenticate messages. |
| ChaCha20 | Fast software encryption without padding. | Never reuse a key/nonce pair; plain ChaCha20 has no integrity. [A3](./secrecy/A3ChaCha20.java) separates Alice/Bob nonces. ChaCha20-Poly1305 adds authentication. |
| AES-GCM | Combines counter-mode encryption with an authentication tag. AEAD also supports authenticated, unencrypted metadata; fast with AES hardware. | IV reuse can destroy secrecy and authentication. [GCM exchange](./ae-pke/A1AgentCommunicationGCM.java) generates an IV per encryption and uses a 128-bit tag. Still needs replay protection. |
| ChaCha20-Poly1305 | AEAD with good software performance. | Still requires unique nonces and replay handling. [PublicSpace](./ae-pke/A2AgentCommunicationPublicSpace.java) uses it to protect Alice's digest on its way to the relay. |
| RSA-OAEP | Encrypt small secrets using the recipient's public key. | Slow, limited plaintext size, no sender authentication. [RSA exchange](./ae-pke/A3AgentCommunicationRSA.java) encrypts short text; [key transport](./keyagreement/A1AgentCommunicationKeyExchange.java) encrypts an AES key and uses GCM for data. Authenticate the public key and explicitly agree on OAEP hash/MGF1 parameters. |

`ECB` in Java's `RSA/ECB/OAEPPadding` name is a naming placeholder, not AES-style
ECB processing. RSA-OAEP's plaintext limit is `modulusBytes - 2*hashBytes - 2`:
use hybrid encryption for larger data, not repeated RSA calls.

### Integrity, identity, and keys

| Used here | Why useful | Limitation and how to address it |
| --- | --- | --- |
| SHA-256 | A compact 32-byte fingerprint, even for a large file. | An attacker can replace both data and an unprotected hash. Authenticate the digest, as in [PublicSpace](./ae-pke/A2AgentCommunicationPublicSpace.java), or use HMAC/signatures. |
| HMAC-SHA256 | Fast integrity and authentication between shared-key holders. | No secrecy or replay protection; either holder can forge tags. [HMAC exchange](./integrity/A1AgentCommunicationHMAC.java) uses `MessageDigest.isEqual` and rejects failures before displaying data. Authenticate sequence numbers too. |
| DH / ECDH | Agree on a secret without transmitting it. ECDH uses smaller keys for comparable security. | Unauthenticated exchanges allow MITM. [DH](./keyagreement/AgentCommunicationDH.java) and [ECDH](./keyagreement/AgentCommunicationECDH.java) also take the first 16 secret bytes as an AES key. Authenticate the handshake; use HKDF to derive keys, binding identities and the transcript. |
| RSA signatures | Publicly verifiable integrity and evidence of the signer, given a trusted public key. | No secrecy or replay protection. [SHA256withRSA](./signatures/SignatureExampleRSA.java) uses PKCS#1 v1.5 signatures; [RSA-PSS](./signatures/SignatureExampleRSAPSS.java) demonstrates a modern randomized alternative with explicit SHA-256/MGF1/salt settings. |
| ECDSA | Compact signatures and public keys. | Needs a trusted public key and secure signing randomness; reusing a signing nonce can expose the private key. [Signed exchange](./signatures/A2AgentCommunicationSignature.java) rejects invalid signatures but does not enforce freshness. |
| PBKDF2 | Salted, deliberately slow password-to-key derivation raises guessing cost. | Weak passwords remain guessable. [KeyDerivation](./signatures/KeyDerivation.java) uses `hunter2`, a fixed salt, PBKDF2-HMAC-SHA1, and 10,000 iterations as demo values. Use a random salt per password and a current calibrated work factor; consider PBKDF2-HMAC-SHA256 or Argon2id. |

Fresh **ephemeral** DH/ECDH keys, erased after use, can provide forward secrecy:
later compromise of a long-term signing key need not expose past session keys.
RSA key transport lacks that property if its RSA decryption key is later compromised.
PBKDF2 is for passwords; HKDF is for high-entropy shared secrets.

## Important details in these exercises

- **Wire order matters.** CBC/CTR/plain ChaCha20 send `ciphertext`, then `IV/nonce`.
  GCM/PublicSpace send `IV/nonce`, then `ciphertext + tag`.
  HMAC/signatures send `message`, then `tag/signature`. Match each receive to its send.
- **IVs/nonces are public.** CBC needs unpredictability; CTR must avoid overlapping
  counter ranges; ChaCha20/AEAD need nonce uniqueness under a key, across both directions.
  The receiver must use the parameters belonging to that ciphertext.
- **Bounded nonce schemes.** [CTR](./secrecy/A2AESInCTRMode.java) sets the first IV byte
  to `2*i` or `2*i+1`, leaving the rest zero; its short messages use only two blocks,
  so counter ranges do not overlap. [ChaCha20](./secrecy/A3ChaCha20.java) puts those
  values in the last nonce byte, with counter 0. These work for ten rounds, but a byte
  wraps after 256 values. Use a larger managed nonce space and separate directional
  keys for longer-lived sessions; preserve uniqueness across restarts.
- **AEAD verification.** Java's `doFinal()` appends/checks the tag.
  `GCMParameterSpec(128, iv)` specifies tag length in **bits**, not IV bytes.
  A wrong key, changed IV, or changed ciphertext should fail authentication, typically
  with `AEADBadTagException`. Reject it before using plaintext.
  Plain ChaCha20 uses `ChaCha20ParameterSpec(nonce, counter)`; ChaCha20-Poly1305
  decryption here uses `IvParameterSpec(nonce)`.
- **CTR bit-flipping.** Since `C = P XOR keystream`, an attacker can calculate
  `C' = C XOR knownPlaintext XOR desiredPlaintext` without the key.
  [A5](./secrecy/A5ActiveMITM.java) asks you to change only the recipient to
  `isp@gmail.com`, padding that line with spaces to preserve its byte length and
  the rest of the message. FMTP is fictional; the server only decrypts and prints.
  AEAD would detect the modified ciphertext.
- **Weak-key recovery.** [A4](./secrecy/A4ExhaustiveSearch.java) varies only three DES
  key bytes: 2^24 byte representations, but 2^21 effective keys due to parity bits.
  Search using the known plaintext and ciphertext, then verify the complete plaintext.
  Equivalent recovered key bytes need not match the original bytes.
- **Cheap bulk transfer.** [PublicSpace](./ae-pke/A2AgentCommunicationPublicSpace.java)
  sends 200 MiB openly, routing only its SHA-256 digest through ChaCha20-Poly1305 and
  AES-GCM links. Bob compares his computed hash with that authenticated digest.
  This saves secure-channel bandwidth, but trusts the relay and does not hide data.
  Transfer identifiers and freshness checks are still needed to stop replay.
- **Public-key substitution.** [RSA key transport](./keyagreement/A1AgentCommunicationKeyExchange.java)
  trusts a key received over the channel. An attacker can replace it; GCM cannot
  repair a compromised handshake. Use certificates, pinned keys, or a handshake
  transcript signed by an already trusted identity.
- **Replay and side channels.** AEAD, HMAC, and signatures alone accept valid old
  messages. Authenticate session IDs, direction, and sequence numbers, and reject
  duplicates. Use `MessageDigest.isEqual` for fixed-length HMAC tags, as illustrated
  by [HMACExample](./integrity/HMACExample.java). Remove the demos' secret-key/shared-secret
  logging in real applications.

## Coding in IntelliJ IDEA or VS Code

### Setup shared by both editors

Use **JDK 21** and UTF-8. Check `java -version` and `javac -version`; the IDE and
terminal can use different JDKs.

This checkout has loose source files: **no Maven/Gradle build file, bundled dependency
JAR, or standard source tree**. `mvn compile` needs a configured Maven project first.
`fri.isp.Agent` and `fri.isp.Environment` come from the external
[communication library](https://github.com/lem-course/isp-communication-model).
Use the course-provided dependency/JAR or that library's build instructions.
It must be on both compile and runtime classpaths; Java's crypto APIs are in the JDK.

When importing into a normal Java project, arrange files according to their declared
packages below the source root (for Maven, `src/main/java`):

| Files in this checkout | Directory below source root | Example main class |
| --- | --- | --- |
| [secrecy/](./secrecy/) | `isp/secrecy/` | `isp.secrecy.A1AESInCBCMode` |
| [integrity/](./integrity/) | `isp/integrity/` | `isp.integrity.A1AgentCommunicationHMAC` |
| [ae-pke/](./ae-pke/) | `isp/` | `isp.A1AgentCommunicationGCM` |
| [keyagreement/](./keyagreement/) | `isp/keyagreement/` | `isp.keyagreement.AgentCommunicationECDH` |
| [signatures/](./signatures/) | `isp/signatures/` | `isp.signatures.A2AgentCommunicationSignature` |

[ae-pke/](./ae-pke/) is a topic folder, **not a Java package**: its files declare
`package isp;`. The source root is the directory *above* `isp`.

### Editor checklist

| IntelliJ IDEA | VS Code |
| --- | --- |
| Create/open a Java project; set **Project SDK** and module SDK to JDK 21. | Install **Extension Pack for Java**; select JDK 21 with **Java: Configure Java Runtime**. |
| Arrange sources as above; mark the directory above `isp` as **Sources Root**. | Open the project folder and configure its source root; unmanaged projects can use the Java extension's source-path settings. |
| Add the communication JAR under **Project Structure > Modules > Dependencies**, or import the configured Maven/Gradle build. | For an unmanaged project, add the JAR via **Java Projects > Referenced Libraries**; otherwise use the build's dependency management. |
| Run/Debug the gutter arrow beside `main()`; use the module containing the dependency. | Use the Java extension's **Run Java / Debug Java** links above `main()` to use the project classpath. |
| Put breakpoints in each agent's `task()`; inspect the Threads panel. | Put breakpoints in each agent's `task()`; inspect Call Stack/threads in Run and Debug. |

### Quick troubleshooting

- **`package fri.isp does not exist`:** missing compile dependency.
  **`NoClassDefFoundError`:** check the runtime classpath too.
- **Package mismatch / main class not found:** check source root, directory layout,
  and fully qualified class name against the table.
- **Program hangs:** inspect both agents for mismatched receives or exceptions.
  Pausing one agent in the debugger can leave its peer waiting for the next message.
- **Padding/tag errors:** check key, transformation, IV/nonce, counter, and receive
  order. Successful unauthenticated decryption alone does not establish integrity.
- **PublicSpace runs out of memory:** its payload alone needs 200 MiB; increase
  the run configuration's heap, e.g. `-Xmx1g`.
- **Terminal classpaths:** Windows separates entries with `;`; macOS/Linux use `:`.
  Quote paths with spaces and rebuild after edits before running compiled classes.

For real network applications, use an established authenticated protocol such as TLS
instead of assembling these teaching exchanges into a custom protocol.
