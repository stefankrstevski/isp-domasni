package isp.practice;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.AEADBadTagException;
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
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * PRACTICE MIDTERM 03 — Secure telemetry channel with replay protection.
 *
 * Sensor and Server:
 * 1) Authenticate their temporary ECDH public keys using long-term ECDSA keys.
 * 2) Derive the same AES-128 session key from the ECDH shared secret.
 * 3) Exchange AES-GCM-protected measurements with authenticated sequence numbers.
 * 4) Reject a replayed message, even though its AES-GCM tag is still valid.
 *
 * This is an educational exercise based on the Java patterns in the ISP homework.
 * As requested in the exercise, it uses SHA-256(shared secret) truncated to 16 bytes
 * for key derivation; real protocols should use an appropriate KDF such as HKDF.
 */
public class Practice_SecureTelemetryReplay03 {
    public static void main(String[] args) throws Exception {
        // GIVEN: Both agents know each other's authentic signing PUBLIC keys.
        // These long-term ECDSA key pairs are NOT the temporary ECDH key pairs.
        final KeyPairGenerator identities = KeyPairGenerator.getInstance("EC");
        identities.initialize(256);
        final KeyPair sensorIdentity = identities.generateKeyPair();
        final KeyPair serverIdentity = identities.generateKeyPair();

        final Environment env = new Environment();

        env.add(new Agent("sensor") {
            @Override
            public void task() throws Exception {
                // STEP 1: Generate a fresh ECDH key pair and send its PUBLIC part.
                final KeyPairGenerator kpgSensor = KeyPairGenerator.getInstance("EC");
                kpgSensor.initialize(256); // Same style as AgentCommunicationECDH.java
                final KeyPair keyPairSensorEphemeral = kpgSensor.generateKeyPair();
                final byte[] publicA = keyPairSensorEphemeral.getPublic().getEncoded();
                send("server", publicA);

                // STEP 2: Sign ("sensor" || A) with the LONG-TERM private key.
                // The temporary ECDH private key is for key agreement, not signing.
                final Signature signer = Signature.getInstance("SHA256withECDSA");
                signer.initSign(sensorIdentity.getPrivate());
                final byte[] identity = "sensor".getBytes(StandardCharsets.UTF_8);
                signer.update(concat(identity, publicA));
                final byte[] sensorSignature = signer.sign();
                send("server", sensorSignature);

                // STEP 3: Receive the server's ephemeral public key B and its
                // signature. A signature is verified over the MESSAGE, not over
                // the signature itself!
                final byte[] publicB = receive("server");
                final byte[] serverSignature = receive("server");
                final PublicKey serverEcdhPublic = KeyFactory.getInstance("EC")
                        .generatePublic(new X509EncodedKeySpec(publicB));

                final Signature verifier = Signature.getInstance("SHA256withECDSA");
                verifier.initVerify(serverIdentity.getPublic()); // Trusted identity key!
                final byte[] serverSignedData = concat(
                        "server".getBytes(StandardCharsets.UTF_8), concat(publicA, publicB));
                verifier.update(serverSignedData);
                if (!verifier.verify(serverSignature)) {
                    throw new SecurityException("Invalid signature from Server");
                }
                print("Server ECDSA signature verified");

                // STEP 4: ECDH = my temporary PRIVATE key + peer temporary PUBLIC key.
                // Both agents independently compute identical secret bytes.
                final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                dh.init(keyPairSensorEphemeral.getPrivate());
                dh.doPhase(serverEcdhPublic, true);
                final byte[] sharedSecret = dh.generateSecret();

                // This exam's KDF rule: SHA-256(shared secret), first 16 bytes.
                // Do not print or send sharedSecret or the AES key.
                final byte[] hashedSecret = MessageDigest.getInstance("SHA-256")
                        .digest(sharedSecret);
                final SecretKeySpec aesKey = new SecretKeySpec(hashedSecret, 0, 16, "AES");

                // STEP 5: Encrypt three measurements with AES-GCM.
                final String[] measurements = {
                        "temperature=21.5", "temperature=22.0", "temperature=21.8"
                };
                final SecureRandom random = new SecureRandom();

                // Keep the exact wire bytes of message #2 for the replay test.
                byte[] savedSequence = null;
                byte[] savedNonce = null;
                byte[] savedCiphertext = null;

                for (int i = 0; i < measurements.length; i++) {
                    final long sequence = i + 1;
                    // Big-endian 8-byte number; send it in the clear, but authenticate it.
                    final byte[] sequenceBytes = ByteBuffer.allocate(Long.BYTES)
                            .putLong(sequence).array();
                    final byte[] nonce = new byte[12]; // GCM nonce, NOT secret
                    random.nextBytes(nonce); // Fresh nonce for each encryption

                    final Cipher encrypt = Cipher.getInstance("AES/GCM/NoPadding");
                    encrypt.init(Cipher.ENCRYPT_MODE, aesKey,
                            new GCMParameterSpec(128, nonce));
                    encrypt.updateAAD(sequenceBytes); // Protect the sequence number
                    final byte[] ciphertext = encrypt.doFinal(
                            measurements[i].getBytes(StandardCharsets.UTF_8));

                    // The GCM tag is already appended to ciphertext by doFinal().
                    send("server", sequenceBytes);
                    send("server", nonce);
                    send("server", ciphertext);
                    print("Sent authenticated measurement #%d", sequence);

                    if (sequence == 2) {
                        savedSequence = sequenceBytes.clone();
                        savedNonce = nonce.clone();
                        savedCiphertext = ciphertext.clone();
                    }
                }

                // STEP 6: Replay EXACT message #2 without re-encrypting it.
                // GCM authentication will still pass. The server must additionally
                // reject the old sequence number to prevent duplicate processing.
                send("server", savedSequence);
                send("server", savedNonce);
                send("server", savedCiphertext);
                print("Replayed measurement #2 without modifying its bytes");
            }
        });

        env.add(new Agent("server") {
            @Override
            public void task() throws Exception {
                // STEP 1: Receive Sensor's ephemeral public key A and signature.
                final byte[] publicA = receive("sensor");
                final byte[] sensorSignature = receive("sensor");
                final PublicKey sensorEcdhPublic = KeyFactory.getInstance("EC")
                        .generatePublic(new X509EncodedKeySpec(publicA));

                // STEP 2: Verify the message ("sensor" || A) using Sensor's
                // TRUSTED long-term PUBLIC key, not the received ECDH public key.
                final Signature verifier = Signature.getInstance("SHA256withECDSA");
                verifier.initVerify(sensorIdentity.getPublic());
                verifier.update(concat("sensor".getBytes(StandardCharsets.UTF_8), publicA));
                if (!verifier.verify(sensorSignature)) {
                    throw new SecurityException("Invalid signature from Sensor");
                }
                print("Sensor ECDSA signature verified");

                // STEP 3: Generate Server's own fresh ECDH pair and sign
                // ("server" || A || B) with Server's LONG-TERM private key.
                final KeyPairGenerator kpgServer = KeyPairGenerator.getInstance("EC");
                kpgServer.initialize(256);
                final KeyPair keyPairServerEphemeral = kpgServer.generateKeyPair();
                final byte[] publicB = keyPairServerEphemeral.getPublic().getEncoded();

                final Signature signer = Signature.getInstance("SHA256withECDSA");
                signer.initSign(serverIdentity.getPrivate());
                signer.update(concat("server".getBytes(StandardCharsets.UTF_8),
                        concat(publicA, publicB)));
                final byte[] serverSignature = signer.sign();
                send("sensor", publicB);       // FIRST send B
                send("sensor", serverSignature); // THEN send its signature

                // STEP 4: Independently derive exactly the same AES-128 key.
                final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                dh.init(keyPairServerEphemeral.getPrivate());
                dh.doPhase(sensorEcdhPublic, true);
                final byte[] sharedSecret = dh.generateSecret();
                final byte[] hashedSecret = MessageDigest.getInstance("SHA-256")
                        .digest(sharedSecret);
                final SecretKeySpec aesKey = new SecretKeySpec(hashedSecret, 0, 16, "AES");

                // STEP 5: Validate three new measurements and one replay.
                long lastAcceptedSequence = 0;
                int accepted = 0;
                int rejected = 0;
                for (int attempt = 1; attempt <= 4; attempt++) {
                    final byte[] sequenceBytes = receive("sensor");
                    final byte[] nonce = receive("sensor");
                    final byte[] ciphertext = receive("sensor");

                    if (sequenceBytes.length != Long.BYTES) {
                        throw new SecurityException("Sequence must be exactly 8 bytes");
                    }
                    if (nonce.length != 12) {
                        throw new SecurityException("GCM nonce must be 12 bytes");
                    }

                    // Verify authentication before considering the plaintext.
                    final Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding");
                    decrypt.init(Cipher.DECRYPT_MODE, aesKey,
                            new GCMParameterSpec(128, nonce));
                    decrypt.updateAAD(sequenceBytes); // SAME AAD bytes as sender
                    final byte[] plaintext;
                    try {
                        plaintext = decrypt.doFinal(ciphertext);
                    } catch (AEADBadTagException ex) {
                        rejected++;
                        print("REJECTED: AES-GCM authentication failed");
                        continue;
                    }

                    final long sequence = ByteBuffer.wrap(sequenceBytes).getLong();
                    if (sequence <= 0 || sequence <= lastAcceptedSequence) {
                        // A valid GCM tag DOES NOT prove the message is fresh.
                        rejected++;
                        print("REPLAY REJECTED: sequence %d, last accepted %d",
                                sequence, lastAcceptedSequence);
                        continue;
                    }

                    // Only now is it safe to process the new measurement.
                    lastAcceptedSequence = sequence;
                    accepted++;
                    print("ACCEPTED #%d: %s", sequence,
                            new String(plaintext, StandardCharsets.UTF_8));
                }

                // STEP 6: Check that no replayed measurement was processed.
                print("Final result: %d accepted, %d rejected", accepted, rejected);
                if (accepted != 3 || rejected != 1) {
                    throw new SecurityException("Unexpected replay-protection result");
                }
            }
        });

        env.connect("sensor", "server");
        env.start();
    }

    // Used only to construct the exact bytes that the signature authenticates.
    private static byte[] concat(byte[] left, byte[] right) {
        byte[] result = Arrays.copyOf(left, left.length + right.length);
        System.arraycopy(right, 0, result, left.length, right.length);
        return result;
    }
}
