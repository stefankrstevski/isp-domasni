# Historical ISP Midterm 1 - Practice Solutions

These are commented reconstructions of two historical programming assignments from the screenshots. They use the same fri.isp.Agent / Environment simulator as the existing homework.

## Practice_OneSidedAuthenticatedKeyExchange01.java

A one-sided authenticated, TLS-like ECDH handshake based on the 2023 screenshot and accompanying full-protocol image.

1. Alice sends her ephemeral ECDH public key A.
2. Server generates B, signs A || B with its long-term RSA private key and encrypts a fresh 32-byte challenge using AES-GCM.
3. Alice checks the RSA signature with the already trusted server public key, derives the AES key from SHA-256(ECDH secret) truncated to 16 bytes, and decrypts the challenge.
4. Alice sends an encrypted SHA-256(password || challenge) response. Server decrypts and verifies it.

Why each part exists: ECDH establishes the shared secret, RSA authenticates the server, AES-GCM provides secrecy and integrity, and a fresh challenge plus password proof authenticates Alice.

## Practice_LamportElectronicLock02.java

The 2021/22 electronic-lock assignment reconstructed from the photos.

1. Alice and Server mutually authenticate their ephemeral ECDH public values using RSA signatures, and establish an AES-GCM channel. Ephemeral ECDH also addresses the optional forward-secrecy requirement.
2. Alice chooses a random seed s and computes H^1000(s), which she securely uploads as the chain anchor.
3. Server derives an HMAC-SHA256 key from its shared password with Lock using PBKDF2-HMAC-SHA256, 1000 iterations and a salt. Lock verifies HMAC before storing the anchor.
4. Alice sends H^999(s), H^998(s), H^997(s). Lock verifies SHA256(token) == stored; on success replaces stored with token. A replayed token is rejected.

## Running

Use JDK 21 and the course isp-communication-model library. The repository currently holds loose Java files and does not include a Maven build. The new files use package isp.practice, so if you move them into a standard Maven project, put them in src/main/java/isp/practice. Run each class main method individually.

Example output:
- One-sided: server prints SUCCESS after validating Alice.
- Electronic lock: three SUCCESS results, followed by FAILURE for the replayed token.

Both source files were compiled and run with Java 21 and a lightweight implementation of the course Agent/Environment API to validate the sequence of sends and receives. This is not a full integration run against the upstream course JAR.

## Questions to defend

- Why is unauthenticated ECDH vulnerable to a man-in-the-middle attack?
- What exact data is signed, who signs it, and who verifies it?
- Which part provides confidentiality, integrity, authentication and forward secrecy?
- Why is the AES-GCM nonce transmitted, and why must it not be reused with the same key?
- How does the server verify the password proof?
- Why does the lock need HMAC rather than a bare SHA-256 digest?
- Why are Lamport tokens sent in reverse order and stored only after verification?
- Why does a replayed token fail?

## Important limitations

These files are educational reference implementations, NOT production TLS/PAKE/lock firmware. They reproduce coursework choices such as direct SHA-256-based ECDH key derivation and 1000 PBKDF2 iterations, which should be replaced by modern reviewed protocols, transcript-bound HKDF and appropriately costly password hashing in real systems. The course Environment simulates message channels, not actual NFC or secure networking.

The supplied historical screenshots are incomplete in places. These implementations follow the visible protocols and fill in reasonable simulation details; they are not claimed to be official model solutions.
