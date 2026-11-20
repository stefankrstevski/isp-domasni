package isp.practice;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
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
import java.util.Arrays;

/**
 * PRACTICE MIDTERM: Alice -> Server -> electronic Lock (historical 2021/22).
 *
 * Covers all screenshot tasks: mutual RSA authentication (+ ephemeral ECDH for
 * forward secrecy), AES-GCM channel, SHA-256 Lamport one-time tokens, PBKDF2-
 * derived HMAC to transfer the chain anchor, and one-time access control.
 *
 * This reproduces the requested 1,000 PBKDF2 iterations FOR EXAM PRACTICE.
 * That work factor is too small for protecting modern production passwords.
 */
public class Practice_LamportElectronicLock02 {
    private static final SecureRandom RNG = new SecureRandom();
    private static final int CHAIN_LENGTH = 1_000;
    private static final int ACCESS_ATTEMPTS = 3; // then 1 intentional replay test
    private static final int GCM_TAG_BITS = 128;
    private static final int PBKDF2_ITERATIONS = 1_000; // historical task requirement

    public static void main(String[] args) throws Exception {
        // The assignment says authentic RSA public keys are known beforehand.
        // Each side uses ONLY its own RSA private key to sign.
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        final KeyPair aliceIdentity = rsa.generateKeyPair();
        final KeyPair serverIdentity = rsa.generateKeyPair();

        // The password for the separate Server-Lock link is not available to Alice.
        final char[] serverLockPassword = "lock-technician-demo".toCharArray();
        Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override public void task() throws Exception {
                // PART 1: mutually authenticated ECDH. Ephemeral private keys
                // are created for this run, not reused as identity keys.
                KeyPair ephemeralA = freshEcKeyPair();
                byte[] publicA = ephemeralA.getPublic().getEncoded();
                send("server", publicA);
                send("server", sign(aliceIdentity, concat(utf8("ALICE"), publicA)));

                byte[] publicB = receive("server");
                byte[] signedTranscript = receive("server");
                // Verify before trusting B: prevents an attacker from swapping
                // the server's ephemeral public key (MITM attack).
                byte[] expectedTranscript = concat(utf8("SERVER"), concat(publicA, publicB));
                if (!verify(serverIdentity.getPublic(), expectedTranscript, signedTranscript)) {
                    throw new SecurityException("Server RSA authentication failed");
                }
                SecretKeySpec aesKey = sessionKey(ephemeralA, decodeEc(publicB));

                // PART 2: create 1,000 successive SHA-256 outputs from a random
                // secret seed. Upload ONLY the last value H^1000(seed).
                byte[] seed = randomBytes(32);
                byte[] chainAnchor = hash(CHAIN_LENGTH, seed);
                sendGcm(this, "server", aesKey, chainAnchor);

                // Wait for confirmation of successful Server -> Lock provisioning
                // before trying to use any one-time access token.
                byte[] ack = receiveGcm(this, "server", aesKey);
                if (!MessageDigest.isEqual(ack, utf8("READY"))) {
                    throw new SecurityException("Lock provisioning failed");
                }

                // PART 4: use tokens in REVERSE hash-chain order: H^999, H^998,
                // H^997, ... . Lock checks SHA256(received) == stored value.
                byte[] lastToken = null;
                for (int i = 0; i < ACCESS_ATTEMPTS; i++) {
                    lastToken = hash(CHAIN_LENGTH - 1 - i, seed);
                    send("lock", lastToken); // models NFC; it is NOT encrypted
                    String decision = new String(receive("lock"), StandardCharsets.UTF_8);
                    print("Access %d: %s", i + 1, decision);
                    if (!"SUCCESS".equals(decision)) {
                        throw new SecurityException("A valid Lamport token was rejected");
                    }
                }

                // Replay one already consumed token. The lock MUST reject it.
                send("lock", lastToken);
                String replayResult = new String(receive("lock"), StandardCharsets.UTF_8);
                print("Replay of last token: %s (expected FAILURE)", replayResult);
                if (!"FAILURE".equals(replayResult)) {
                    throw new SecurityException("Replay attack was accepted");
                }
            }
        });

        env.add(new Agent("server") {
            @Override public void task() throws Exception {
                // PART 1: verify Alice's RSA signature before accepting A.
                byte[] publicA = receive("alice");
                byte[] signedA = receive("alice");
                if (!verify(aliceIdentity.getPublic(), concat(utf8("ALICE"), publicA), signedA)) {
                    throw new SecurityException("Alice RSA authentication failed");
                }
                KeyPair ephemeralB = freshEcKeyPair();
                byte[] publicB = ephemeralB.getPublic().getEncoded();
                byte[] signedTranscript = sign(serverIdentity,
                        concat(utf8("SERVER"), concat(publicA, publicB)));
                send("alice", publicB);
                send("alice", signedTranscript);
                SecretKeySpec aesKey = sessionKey(ephemeralB, decodeEc(publicA));

                // PART 2: authenticated encryption hides the uploaded anchor
                // and rejects tampering. IV is sent separately; tag is in CT.
                byte[] chainAnchor = receiveGcm(this, "alice", aesKey);
                if (chainAnchor.length != 32) {
                    throw new SecurityException("Invalid SHA-256 chain anchor");
                }

                // PART 3: authenticate provisioning to the low-power lock.
                // PBKDF2 derives an HMAC key from the shared password and salt.
                byte[] salt = randomBytes(16);
                SecretKeySpec macKey = passwordMacKey(serverLockPassword, salt);
                byte[] tag = mac(macKey, chainAnchor);
                send("lock", chainAnchor);
                send("lock", salt);
                send("lock", tag);
                String status = new String(receive("lock"), StandardCharsets.UTF_8);
                if (!"STORED".equals(status)) {
                    throw new SecurityException("Lock refused token-chain anchor");
                }
                sendGcm(this, "alice", aesKey, utf8("READY"));
                print("Provisioned lock with authenticated chain anchor");
            }
        });

        env.add(new Agent("lock") {
            @Override public void task() throws Exception {
                // PART 3: verify MAC BEFORE storing server's token anchor.
                byte[] candidateAnchor = receive("server");
                byte[] salt = receive("server");
                byte[] receivedTag = receive("server");
                SecretKeySpec macKey = passwordMacKey(serverLockPassword, salt);
                byte[] expectedTag = mac(macKey, candidateAnchor);
                if (!MessageDigest.isEqual(receivedTag, expectedTag)) {
                    send("server", utf8("REJECTED"));
                    return; // never install an unauthenticated token
                }
                byte[] storedToken = candidateAnchor;
                send("server", utf8("STORED"));

                // PART 4: accept a token t if H(t) equals the CURRENT stored
                // value, then replace stored value by t. This invalidates t
                // itself for any later attempt (one-time-use property).
                for (int i = 0; i < ACCESS_ATTEMPTS + 1; i++) {
                    byte[] token = receive("alice");
                    boolean valid = MessageDigest.isEqual(sha256(token), storedToken);
                    if (valid) {
                        storedToken = token; // update only on successful verify
                    }
                    send("alice", utf8(valid ? "SUCCESS" : "FAILURE"));
                    print("Attempt %d: %s", i + 1, valid ? "SUCCESS" : "FAILURE");
                }
            }
        });

        env.connect("alice", "server");
        env.connect("server", "lock");
        env.connect("alice", "lock");
        env.start();
    }

    // ------------ Shared helper functions (not shared secret keys) -----------

    private static KeyPair freshEcKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), RNG);
        return generator.generateKeyPair();
    }

    private static PublicKey decodeEc(byte[] encoded) throws Exception {
        return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(encoded));
    }

    private static SecretKeySpec sessionKey(KeyPair mine, PublicKey theirs) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(mine.getPrivate());
        ka.doPhase(theirs, true);
        // SHA256(ECDH secret), truncated to AES-128 for a compact lab example.
        // Production protocols use transcript-bound HKDF and direction keys.
        return new SecretKeySpec(Arrays.copyOf(sha256(ka.generateSecret()), 16), "AES");
    }

    private static byte[] sign(KeyPair identity, byte[] message) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(identity.getPrivate(), RNG);
        signer.update(message);
        return signer.sign();
    }

    private static boolean verify(PublicKey key, byte[] message, byte[] sig) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(key);
        verifier.update(message);
        return verifier.verify(sig);
    }

    private static void sendGcm(Agent sender, String recipient, SecretKeySpec key,
                                byte[] plaintext) throws Exception {
        byte[] nonce = randomBytes(12);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, nonce));
        sender.send(recipient, nonce);        // public IV; unique for this key
        sender.send(recipient, cipher.doFinal(plaintext)); // CT + GCM tag
    }

    private static byte[] receiveGcm(Agent receiver, String sender, SecretKeySpec key)
            throws Exception {
        byte[] nonce = receiver.receive(sender);
        byte[] ciphertext = receiver.receive(sender);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, nonce));
        return cipher.doFinal(ciphertext); // rejects tampering automatically
    }

    private static SecretKeySpec passwordMacKey(char[] password, byte[] salt) throws Exception {
        // Assignment explicitly specifies PBKDF2-HMAC-SHA256, 1000 iterations.
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, 256);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] key = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(key, "HmacSHA256");
        } finally {
            spec.clearPassword();
        }
    }

    private static byte[] mac(SecretKeySpec key, byte[] message) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        return mac.doFinal(message);
    }

    private static byte[] hash(int times, byte[] initial) throws Exception {
        byte[] current = initial.clone();
        for (int i = 0; i < times; i++) {
            current = sha256(current);
        }
        return current;
    }

    private static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RNG.nextBytes(bytes);
        return bytes;
    }

    private static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
