package isp.practice;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
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
 * PRACTICE MIDTERM: a simplified, TLS-like authenticated ECDH handshake.
 *
 * Based on the supplied 2023 midterm screenshot (the screenshot is cut off,
 * so the remaining protocol steps are taken from the accompanying image).
 * Alice trusts the server's RSA public key in advance. The server knows Alice's
 * password. RSA authenticates the server; a challenge authenticates Alice.
 *
 * Run this file using the course fri.isp communication-model dependency.
 * Educational protocol only: do not build production TLS this way.
 */
public class Practice_OneSidedAuthenticatedKeyExchange01 {
    private static final SecureRandom RNG = new SecureRandom();
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_NONCE_BYTES = 12;

    public static void main(String[] args) throws Exception {
        // Initial setting: the server owns the RSA private key. Alice ONLY sees
        // the corresponding public key, not the private key.
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        final KeyPair serverIdentity = rsa.generateKeyPair();
        final PublicKey trustedServerPublicKey = serverIdentity.getPublic();
        final String sharedPassword = "midterm-demo-password";

        Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override public void task() throws Exception {
                // 1) Ephemeral ECDH: private value a never leaves Alice.
                KeyPair ephemeralA = freshEcdhPair();
                byte[] publicA = ephemeralA.getPublic().getEncoded();
                send("server", publicA);

                // 3) Receive server's ECDH public key B, RSA signature over
                // A || B, and an AES-GCM-encrypted random challenge.
                byte[] publicB = receive("server");
                byte[] serverSignature = receive("server");
                byte[] challengeNonce = receive("server");
                byte[] encryptedChallenge = receive("server");

                // VERIFY FIRST: without this check, a MITM can replace B and
                // negotiate a secret with Alice. The trusted RSA public key
                // must come from initial configuration, not this channel.
                if (!verify(trustedServerPublicKey, concat(publicA, publicB), serverSignature)) {
                    throw new SecurityException("Server signature invalid: abort handshake");
                }

                SecretKeySpec sessionKey = deriveAes128(ephemeralA, decodeEcPublic(publicB));
                byte[] challenge = decryptGcm(sessionKey, challengeNonce, encryptedChallenge);
                if (challenge.length != 32) {
                    throw new SecurityException("Expected a 256-bit server challenge");
                }

                // 3) Password proof requested in the historical assignment:
                // SHA256(password || challenge), encrypted with the session key.
                // A fresh challenge prevents reusing an older successful proof.
                byte[] response = sha256(concat(sharedPassword.getBytes(StandardCharsets.UTF_8), challenge));
                byte[] responseNonce = freshNonce();
                send("server", responseNonce);
                send("server", encryptGcm(sessionKey, responseNonce, response));
                print("Verified server signature and sent encrypted password proof");
            }
        });

        env.add(new Agent("server") {
            @Override public void task() throws Exception {
                // 2) Generate an independent ephemeral keypair. Only public B
                // is disclosed, and both peers independently derive the SAME
                // ECDH secret (the secret itself is never transmitted).
                byte[] publicA = receive("alice");
                PublicKey aliceEphemeralPublic = decodeEcPublic(publicA);
                KeyPair ephemeralB = freshEcdhPair();
                byte[] publicB = ephemeralB.getPublic().getEncoded();
                SecretKeySpec sessionKey = deriveAes128(ephemeralB, aliceEphemeralPublic);

                // Bind BOTH ECDH public values to the authenticated handshake.
                byte[] signature = sign(serverIdentity, concat(publicA, publicB));
                byte[] challenge = new byte[32];
                RNG.nextBytes(challenge);
                byte[] challengeNonce = freshNonce();
                byte[] encryptedChallenge = encryptGcm(sessionKey, challengeNonce, challenge);

                // The receive() calls on Alice's side MUST follow this order.
                send("alice", publicB);
                send("alice", signature);
                send("alice", challengeNonce); // nonce is public, not secret
                send("alice", encryptedChallenge); // includes GCM auth tag

                // 4) The server accepts Alice only after decrypting and checking
                // the proof. GCM also rejects modified ciphertexts/auth tags.
                byte[] responseNonce = receive("alice");
                byte[] encryptedResponse = receive("alice");
                byte[] response = decryptGcm(sessionKey, responseNonce, encryptedResponse);
                byte[] expected = sha256(concat(sharedPassword.getBytes(StandardCharsets.UTF_8), challenge));
                if (!MessageDigest.isEqual(response, expected)) {
                    throw new SecurityException("Wrong password proof: Alice NOT authenticated");
                }
                print("SUCCESS: server authenticated by signature; Alice authenticated by challenge");
            }
        });

        env.connect("alice", "server");
        env.start();
    }

    private static KeyPair freshEcdhPair() throws Exception {
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(new ECGenParameterSpec("secp256r1"), RNG);
        return ec.generateKeyPair();
    }

    private static PublicKey decodeEcPublic(byte[] encoded) throws Exception {
        return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(encoded));
    }

    private static SecretKeySpec deriveAes128(KeyPair mine, PublicKey theirs) throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(mine.getPrivate());
        agreement.doPhase(theirs, true);
        byte[] secret = agreement.generateSecret();
        // EXACTLY as the old task asks: SHA-256(shared secret), first 16 bytes.
        // In production use HKDF with handshake transcript and separate keys.
        return new SecretKeySpec(Arrays.copyOf(sha256(secret), 16), "AES");
    }

    private static byte[] sign(KeyPair identity, byte[] message) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(identity.getPrivate(), RNG);
        signature.update(message);
        return signature.sign();
    }

    private static boolean verify(PublicKey publicKey, byte[] message, byte[] sig) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(message);
        return signature.verify(sig);
    }

    private static byte[] freshNonce() {
        byte[] iv = new byte[GCM_NONCE_BYTES];
        RNG.nextBytes(iv); // never reuse a (key, nonce) pair in AES-GCM
        return iv;
    }

    private static byte[] encryptGcm(SecretKeySpec key, byte[] nonce, byte[] plaintext) throws Exception {
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, nonce));
        return aes.doFinal(plaintext); // Java appends authentication tag
    }

    private static byte[] decryptGcm(SecretKeySpec key, byte[] nonce, byte[] ciphertext) throws Exception {
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, nonce));
        return aes.doFinal(ciphertext); // invalid tag => AEADBadTagException
    }

    private static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
