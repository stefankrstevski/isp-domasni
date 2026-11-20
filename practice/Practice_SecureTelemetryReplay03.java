package isp.practice;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
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
 * PRACTICE MIDTERM 03 — Secure telemetry channel with replay protection.
 *
 * ORIGINAL PRACTICE TASK, inspired by the scope and structure of the earlier
 * midterms and the homework (ECDH, signatures, AES-GCM and agent messaging).
 * This is NOT an official previous-midterm question or solution.
 *
 * Scenario:
 *   sensor -> server sends three temperature measurements securely.
 *   An attacker later replays the second encrypted measurement verbatim.
 *
 * REQUIREMENTS:
 *   1. Sensor and Server have pre-trusted long-term EC SIGNING public keys.
 *      No certificate/PKI implementation is required.
 *   2. Each creates a NEW ephemeral EC keypair for ECDH (separate from its
 *      long-term signing keypair). They authenticate the exchange with ECDSA.
 *   3. Each derives the same AES-128 key:
 *        first 16 bytes of SHA256(ECDH_shared_secret).
 *      This simplified KDF is prescribed for this practice exercise.
 *   4. Sensor sends 3 AES-GCM messages under the session key.
 *      The wire format is [sequence (8 bytes), nonce (12 bytes), CT+tag].
 *      The sequence number MUST be authenticated as GCM AAD, even though it
 *      is transmitted in the clear.
 *   5. Server verifies GCM authentication, then checks that the sequence
 *      is strictly greater than the last accepted sequence. Only then does
 *      it process the measurement and update its counter.
 *   6. Sensor resends the EXACT same bytes from message #2. Server must
 *      reject the replay (not process it a second time).
 *
 * GOALS: Key agreement, mutual authentication, confidentiality, integrity,
 * key-holder authentication, and replay detection.
 *
 * Deliberately unfinished. Fill ALL // TODO sections yourself.
 * The TODO exceptions make the starting file compile but stop execution until
 * you implement it; a successful compile is NOT a passing assignment.
 */
public class Practice_SecureTelemetryReplay03 {
    private static final SecureRandom RNG = new SecureRandom();
    private static final int AES_KEY_BYTES = 16;
    private static final int NONCE_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;

    public static void main(String[] args) throws Exception {
        // GIVEN: identity keys are provisioned securely beforehand.
        // The long-term private keys must NOT be transmitted.
        final KeyPairGenerator identities = KeyPairGenerator.getInstance("EC");
        identities.initialize(new ECGenParameterSpec("secp256r1"));
        final KeyPair sensorIdentity = identities.generateKeyPair();
        final KeyPair serverIdentity = identities.generateKeyPair();

        final Environment env = new Environment();

        env.add(new Agent("sensor") {
            @Override
            public void task() throws Exception {
                // PART 1 — Generate NEW ephemeral ECDH keypair (not identity key).
                // TODO 01: Generate a secp256r1 EC keypair for ECDH.
                // TODO 02: Serialize and send the ephemeral public key A.
                // TODO 03: Sign the bytes ("sensor" || A) using the sensor's
                //          LONG-TERM ECDSA private key; send the signature.
                //          Use SHA256withECDSA.

                // PART 2 — Authenticate the server's ECDH contribution.
                // TODO 04: Receive server ephemeral public key B and its signature.
                // TODO 05: Verify server signature covering ("server" || A || B)
                //          with the pre-trusted serverIdentity PUBLIC key.
                //          If invalid, abort BEFORE accepting the shared key.
                // TODO 06: Use your ECDH PRIVATE key and server's ECDH PUBLIC key
                //          to derive shared secret -> AES-128 session key.
                //          Take SHA256(secret) and its first 16 bytes.

                // PART 3 — Send a protected stream.
                // TODO 07: Send these measurements, using sequence numbers 1,2,3:
                //          "temperature=21.5", "temperature=22.0", "temperature=21.8"
                //          For EACH message create a fresh 12-byte GCM nonce.
                //          Use a 128-bit authentication tag.
                //          Authenticate its 8-byte sequence as GCM AAD.
                //          Send in EXACT order: seqBytes, nonce, ciphertext+tag.
                //          Save all three byte[] components of message #2.

                // PART 4 — Deliberately simulate a replay attack.
                // TODO 08: Send the saved seqBytes, nonce and ciphertext+tag
                //          from message #2 again, completely unchanged.
                //          Never re-encrypt here: this is a replay test.

                // TODO 09 (optional): log "Sensor finished sending".
                throw new UnsupportedOperationException("TODO sensor tasks 01-09");
            }
        });

        env.add(new Agent("server") {
            @Override
            public void task() throws Exception {
                // PART 1 — Authenticate Sensor.
                // TODO 10: Receive A and the sensor signature in the exact
                //          order in which Sensor sends them.
                // TODO 11: Verify ("sensor" || A) using sensorIdentity PUBLIC key.
                //          Abort if verification fails.

                // PART 2 — Complete signed key exchange.
                // TODO 12: Generate own NEW ephemeral EC keypair B.
                // TODO 13: Sign ("server" || A || B) using serverIdentity PRIVATE
                //          key, then send B and signature in that order.
                // TODO 14: Derive same AES-128 key using own ephemeral PRIVATE
                //          key plus Sensor's ephemeral PUBLIC key.

                // PART 3 — Receive three messages and one replay.
                long lastAcceptedSequence = 0;
                for (int attempt = 1; attempt <= 4; attempt++) {
                    // TODO 15: Receive seqBytes, nonce, CT+tag in wire order.
                    // TODO 16: Decrypt using AES/GCM/NoPadding, same 128-bit
                    //          tag length, and authenticate seqBytes via AAD.
                    //          Reject authentication failures.
                    // TODO 17: Interpret seqBytes as signed big-endian long;
                    //          reject <= lastAcceptedSequence (or invalid <=0).
                    // TODO 18: For acceptable message ONLY: update the
                    //          lastAcceptedSequence, then print temperature.
                    // TODO 19: For replayed #2: print "REPLAY REJECTED";
                    //          do not update counter or process temperature.
                    //          Rejection should NOT block/hang the other agent.
                    throw new UnsupportedOperationException("TODO server receive tasks 15-19");
                }

                // TODO 20: Confirm exactly 3 messages accepted and 1 rejected.
                throw new UnsupportedOperationException("TODO server tasks 10-20");
            }
        });

        env.connect("sensor", "server");
        env.start();
    }

    // -------------------- Optional helper scaffolding --------------------
    // You may freely change/delete these signatures as you implement the task.
    // They are deliberately NOT filled in for you.

    private static KeyPair newEphemeralEcKeyPair() throws Exception {
        // TODO H1: Return a fresh EC secp256r1 keypair.
        throw new UnsupportedOperationException("TODO H1");
    }

    private static byte[] sign(byte[] message, KeyPair signingKeys) throws Exception {
        // TODO H2: Use SHA256withECDSA and signingKeys.getPrivate().
        throw new UnsupportedOperationException("TODO H2");
    }

    private static void verifyOrThrow(byte[] message, byte[] signature,
                                      PublicKey trustedSignerPublicKey) throws Exception {
        // TODO H3: Verify SHA256withECDSA using trustedSignerPublicKey.
        //          Throw SecurityException on failure.
        throw new UnsupportedOperationException("TODO H3");
    }

    private static PublicKey decodeEcPublic(byte[] encoded) throws Exception {
        // TODO H4: X509EncodedKeySpec + KeyFactory.getInstance("EC").
        throw new UnsupportedOperationException("TODO H4");
    }

    private static SecretKeySpec deriveSessionKey(KeyPair myEphemeralKeys,
                                                   PublicKey peerEphemeralPublic) throws Exception {
        // TODO H5: KeyAgreement.getInstance("ECDH"), init private,
        //          doPhase(peer public, true), generateSecret().
        //          SHA-256 the secret; first AES_KEY_BYTES -> SecretKeySpec.
        throw new UnsupportedOperationException("TODO H5");
    }

    private static byte[] randomNonce() {
        // TODO H6: Generate NONCE_BYTES cryptographically random bytes.
        throw new UnsupportedOperationException("TODO H6");
    }

    private static byte[] encryptGcm(SecretKeySpec aesKey, byte[] nonce,
                                     byte[] seqBytes, byte[] plaintext) throws Exception {
        // TODO H7: Cipher AES/GCM/NoPadding; ENCRYPT_MODE; GCMParameterSpec.
        //          Call updateAAD(seqBytes) BEFORE doFinal(plaintext).
        throw new UnsupportedOperationException("TODO H7");
    }

    private static byte[] decryptGcm(SecretKeySpec aesKey, byte[] nonce,
                                     byte[] seqBytes, byte[] ciphertextAndTag) throws Exception {
        // TODO H8: Mirror H7 using DECRYPT_MODE, SAME seqBytes as AAD.
        //          If the tag fails, doFinal throws AEADBadTagException.
        throw new UnsupportedOperationException("TODO H8");
    }

    private static byte[] sequenceBytes(long sequence) {
        // TODO H9: Use ByteBuffer.allocate(Long.BYTES).putLong(sequence).array().
        throw new UnsupportedOperationException("TODO H9");
    }

    private static long decodeSequence(byte[] encoded) {
        // TODO H10: Validate length == Long.BYTES, then ByteBuffer.wrap(...)
        //           .getLong(). Use same byte order as H9.
        throw new UnsupportedOperationException("TODO H10");
    }

    private static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] concat(byte[] left, byte[] right) {
        byte[] result = Arrays.copyOf(left, left.length + right.length);
        System.arraycopy(right, 0, result, left.length, right.length);
        return result;
    }
}
