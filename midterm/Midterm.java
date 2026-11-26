package isp.handson;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Secure Report Submission -- completed from the student's original draft.
 * The agent named "sensor" plays Alice's role in the exam protocol.
 * RSA-3072, P-256 ECDH (SunEC), HKDF-SHA256 and ChaCha20-Poly1305.
 * This is a reference reconstruction, not the original submitted exam code.
 */
public class Midterm {
    public static void main(String[] args) throws Exception {
        // SETUP: Both agents already know each other's authentic RSA public keys.
        // RSA identity keys are distinct from the temporary ECDH key pairs.
        final KeyPairGenerator identities = KeyPairGenerator.getInstance("RSA");
        // Java 21 SunRsaSign defaults to 3072-bit RSA.
        final KeyPair sensorIdentity = identities.generateKeyPair();
        final KeyPair serverIdentity = identities.generateKeyPair();
        final int signatureLength = 3072 / 8; // 384 bytes per RSA signature.

        final Environment env = new Environment();

        env.add(new Agent("sensor") {
            @Override
            public void task() throws Exception {
                try {
                    // STEP 1: Generate a fresh ECDH pair and send public key A.
                    final KeyPairGenerator kpgSensor = KeyPairGenerator.getInstance("EC");
                    kpgSensor.initialize(256); // P-256 on the standard Java 21 SunEC provider.
                    final KeyPair keyPairSensorEphemeral = kpgSensor.generateKeyPair();
                    final byte[] publicA = keyPairSensorEphemeral.getPublic().getEncoded();
                    send("server", publicA);

                    // STEP 3: Receive B FIRST and then the Server's RSA signature.
                    final byte[] publicB = receive("server");
                    final byte[] serverSignature = receive("server");

                    // Verify the original signed bytes A || B using the trusted RSA key.
                    final Signature verifier = Signature.getInstance("SHA256withRSA");
                    verifier.initVerify(serverIdentity.getPublic());
                    final byte[] serverSignedData = concat(publicA, publicB);
                    verifier.update(serverSignedData);
                    if (!verifier.verify(serverSignature)) {
                        throw new SecurityException("Invalid signature from Server");
                    }
                    print("Server RSA signature verified");

                    // Decode the authenticated, ephemeral EC public key B.
                    final PublicKey serverEcdhPublic = KeyFactory.getInstance("EC")
                            .generatePublic(new X509EncodedKeySpec(publicB));

                    // STEP 4: Calculate Z = ECDH(my private key, peer public key).
                    final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                    dh.init(keyPairSensorEphemeral.getPrivate());
                    dh.doPhase(serverEcdhPublic, true);
                    final byte[] sharedSecret = dh.generateSecret();

                    // t = SHA256(A || B). Public transcript hash for this session.
                    final byte[] t = MessageDigest.getInstance("SHA-256")
                            .digest(concat(publicA, publicB));

                    // HKDF Extract: PRK = HMAC-SHA256(t, Z).
                    final Mac hmac = Mac.getInstance("HmacSHA256");
                    hmac.init(new SecretKeySpec(t, "HmacSHA256"));
                    final byte[] prk = hmac.doFinal(sharedSecret);

                    // HKDF Expand: each 32-byte key is one HMAC output block.
                    // doFinal resets Mac to its initialized state (same PRK key).
                    hmac.init(new SecretKeySpec(prk, "HmacSHA256"));
                    final byte[] kAS = hmac.doFinal(concat(
                            "alice-to-server".getBytes(StandardCharsets.UTF_8), new byte[]{0x01}));
                    final byte[] kSA = hmac.doFinal(concat(
                            "server-to-alice".getBytes(StandardCharsets.UTF_8), new byte[]{0x01}));
                    final SecretKeySpec aliceToServerKey = new SecretKeySpec(kAS, "ChaCha20");
                    final SecretKeySpec serverToAliceKey = new SecretKeySpec(kSA, "ChaCha20");

                    // STEP 5: Sign t || m with Alice's long-term RSA PRIVATE key.
                    final byte[] m = "Report: all systems operational."
                            .getBytes(StandardCharsets.UTF_8);
                    final Signature signer = Signature.getInstance("SHA256withRSA");
                    signer.initSign(sensorIdentity.getPrivate());
                    signer.update(concat(t, m));
                    final byte[] signature = signer.sign();

                    // Encrypt signature || m (NOT t || m) with the Alice-to-Server key.
                    final Cipher encrypt = Cipher.getInstance("ChaCha20-Poly1305");
                    encrypt.init(Cipher.ENCRYPT_MODE, aliceToServerKey);
                    final byte[] ciphertext = encrypt.doFinal(concat(signature, m));
                    // Provider generates a fresh 12-byte nonce; it is public.
                    // doFinal includes the 16-byte Poly1305 tag in ciphertext.
                    send("server", encrypt.getIV());
                    send("server", ciphertext);

                    // STEP 7: Decrypt receipt using the opposite directional key.
                    final byte[] receiptNonce = receive("server");
                    final byte[] encryptedReceipt = receive("server");
                    if (receiptNonce.length != 12) {
                        throw new SecurityException("Invalid receipt nonce");
                    }
                    final Cipher decrypt = Cipher.getInstance("ChaCha20-Poly1305");
                    decrypt.init(Cipher.DECRYPT_MODE, serverToAliceKey,
                            new IvParameterSpec(receiptNonce));
                    final byte[] receivedDigest = decrypt.doFinal(encryptedReceipt);

                    // Report success ONLY if the authenticated digest matches our report.
                    final byte[] expectedDigest = MessageDigest.getInstance("SHA-256").digest(m);
                    if (!MessageDigest.isEqual(expectedDigest, receivedDigest)) {
                        throw new SecurityException("Receipt does not match report");
                    }
                    print("SUCCESS: server accepted my report");
                } catch (Exception ex) {
                    // The exam permits terminating the process to unblock a waiting peer.
                    print("ABORT: %s", ex.toString());
                    System.exit(1);
                }
            }
        });

        env.add(new Agent("server") {
            @Override
            public void task() throws Exception {
                try {
                    // STEP 2: Alice sends ONLY A at first, not a signature.
                    final byte[] publicA = receive("sensor");
                    final PublicKey sensorEcdhPublic = KeyFactory.getInstance("EC")
                            .generatePublic(new X509EncodedKeySpec(publicA));

                    // Generate Server's fresh ECDH pair, in the same group as Alice.
                    final KeyPairGenerator kpgServer = KeyPairGenerator.getInstance("EC");
                    kpgServer.initialize(256);
                    final KeyPair keyPairServerEphemeral = kpgServer.generateKeyPair();
                    final byte[] publicB = keyPairServerEphemeral.getPublic().getEncoded();

                    // Sign A || B with Server's long-term RSA PRIVATE key.
                    final Signature signer = Signature.getInstance("SHA256withRSA");
                    signer.initSign(serverIdentity.getPrivate());
                    signer.update(concat(publicA, publicB));
                    final byte[] serverSignature = signer.sign();
                    send("sensor", publicB);
                    send("sensor", serverSignature);

                    // STEP 4: Independently calculate exactly the same Z.
                    final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                    dh.init(keyPairServerEphemeral.getPrivate());
                    dh.doPhase(sensorEcdhPublic, true);
                    final byte[] sharedSecret = dh.generateSecret();

                    // Same transcript hash and EXACT same HKDF inputs as Alice.
                    final byte[] t = MessageDigest.getInstance("SHA-256")
                            .digest(concat(publicA, publicB));
                    final Mac hmac = Mac.getInstance("HmacSHA256");
                    hmac.init(new SecretKeySpec(t, "HmacSHA256"));
                    final byte[] prk = hmac.doFinal(sharedSecret);

                    hmac.init(new SecretKeySpec(prk, "HmacSHA256"));
                    final byte[] kAS = hmac.doFinal(concat(
                            "alice-to-server".getBytes(StandardCharsets.UTF_8), new byte[]{0x01}));
                    final byte[] kSA = hmac.doFinal(concat(
                            "server-to-alice".getBytes(StandardCharsets.UTF_8), new byte[]{0x01}));
                    final SecretKeySpec aliceToServerKey = new SecretKeySpec(kAS, "ChaCha20");
                    final SecretKeySpec serverToAliceKey = new SecretKeySpec(kSA, "ChaCha20");

                    // STEP 6: Receive nonce, then encrypted signature || report.
                    final byte[] nonce = receive("sensor");
                    final byte[] ciphertext = receive("sensor");
                    if (nonce.length != 12) {
                        throw new SecurityException("Invalid report nonce");
                    }
                    final Cipher decrypt = Cipher.getInstance("ChaCha20-Poly1305");
                    decrypt.init(Cipher.DECRYPT_MODE, aliceToServerKey, new IvParameterSpec(nonce));
                    final byte[] plaintext = decrypt.doFinal(ciphertext); // Rejects invalid AEAD tag.

                    // RSA-3072 signature occupies the first 384 bytes.
                    // Check the length before splitting; this exercise uses a nonempty report.
                    if (plaintext.length <= signatureLength) {
                        throw new SecurityException("Missing signature or report");
                    }
                    final byte[] sensorSignature = Arrays.copyOfRange(plaintext, 0, signatureLength);
                    final byte[] m = Arrays.copyOfRange(plaintext, signatureLength, plaintext.length);

                    // Verify t || m, NOT just m. Use Alice's trusted RSA public key.
                    final Signature verifier = Signature.getInstance("SHA256withRSA");
                    verifier.initVerify(sensorIdentity.getPublic());
                    verifier.update(concat(t, m));
                    if (!verifier.verify(sensorSignature)) {
                        throw new SecurityException("Invalid signature from Sensor (Alice)");
                    }

                    // Only accept after BOTH AEAD and RSA verification have succeeded.
                    print("Report accepted: %s", new String(m, StandardCharsets.UTF_8));

                    // Receipt = SHA256(m), encrypted using the Server-to-Alice key.
                    final byte[] receipt = MessageDigest.getInstance("SHA-256").digest(m);
                    final Cipher encrypt = Cipher.getInstance("ChaCha20-Poly1305");
                    encrypt.init(Cipher.ENCRYPT_MODE, serverToAliceKey);
                    final byte[] encryptedReceipt = encrypt.doFinal(receipt);
                    send("sensor", encrypt.getIV());
                    send("sensor", encryptedReceipt);
                } catch (Exception ex) {
                    print("ABORT: %s", ex.toString());
                    System.exit(1);
                }
            }
        });

        env.connect("sensor", "server");
        env.start();
    }

    // The only helper: join byte arrays in the order specified by the exam.
    private static byte[] concat(byte[] left, byte[] right) {
        final byte[] result = Arrays.copyOf(left, left.length + right.length);
        System.arraycopy(right, 0, result, left.length, right.length);
        return result;
    }
}
