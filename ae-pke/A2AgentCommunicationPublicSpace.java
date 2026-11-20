package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * TASK:
 * We want to send a large chunk of data from Alice to Bob while maintaining its integrity and considering
 * the limitations of communication channels -- we have three such channels:
 * - Alice to Bob: an insecure channel, but has high bandwidth and can thus transfer large files
 * - Alice to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * - Bob to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * <p>
 * The plan is to make use of the public-space technique:
 * - Alice creates the data and computes its digest
 * - Alice sends the data to Bob, and sends the encrypted digest to Public Space
 * - Channel between Alice and Public space is secured with ChaCha20-Poly1305 (Alice and Public space share
 * a ChaCha20 key)
 * - Public space forwards the digest to Bob
 * - The channel between Public Space and Bob is secured with AES in GCM mode (Bob and Public space share
 * an AES key)
 * - Bob receives the data from Alice and the digest from Public space
 * - Bob computes the digest over the received data and compares it to the received digest
 * <p>
 * Both secure channels use authenticated encryption, so every encryption needs
 * a fresh IV (nonce). Send the IV together with the ciphertext over the same
 * channel and use it for decryption.
 * <p>
 * Further instructions are given below.
 * <p>
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Cipher.html
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/spec/GCMParameterSpec.html
 */
public class A2AgentCommunicationPublicSpace {
    public static void main(String[] args) throws Exception {
        final Environment env = new Environment();

        // Create a ChaCha20 key that is used by Alice and the public-space
        final Key aliceKey = KeyGenerator.getInstance("ChaCha20").generateKey();
        // Create an AES key that is used by Bob and the public-space
        final Key bobKey = KeyGenerator.getInstance("AES").generateKey();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // a payload of 200 MB
                final byte[] data = new byte[200 * 1024 * 1024];
                new SecureRandom().nextBytes(data);

                // Alice sends the data directly to Bob
                // The channel between Alice and Bob is not secured
                // Alice then computes the digest of the data and sends the digest to public-space
                // The channel between Alice and the public-space is secured with ChaCha20-Poly1305
                // Use the key that you have created above.
                send("bob", data);
                final byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
                final Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
                cipher.init(Cipher.ENCRYPT_MODE, aliceKey);
                final byte[] ct = cipher.doFinal(digest);
                send("public-space", cipher.getIV());
                send("public-space", ct);
            }
        });

        env.add(new Agent("public-space") {
            @Override
            public void task() throws Exception {
                // Receive the encrypted digest from Alice and decrypt ChaCha20 and
                // the key that you share with Alice
                // Encrypt the digest with AES-GCM and the key that you share with Bob and
                // send the encrypted digest to Bob
                final byte[] nonce = receive("alice");
                final byte[] ct = receive("alice");
                final Cipher decrypt = Cipher.getInstance("ChaCha20-Poly1305");
                decrypt.init(Cipher.DECRYPT_MODE, aliceKey, new IvParameterSpec(nonce));
                final byte[] digest = decrypt.doFinal(ct);

                final Cipher encrypt = Cipher.getInstance("AES/GCM/NoPadding");
                encrypt.init(Cipher.ENCRYPT_MODE, bobKey);
                final byte[] encryptedDigest = encrypt.doFinal(digest);
                send("bob", encrypt.getIV());
                send("bob", encryptedDigest);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // Receive the data from Alice and compute the digest over it using SHA-256
                // Receive the encrypted digest from the public-space, decrypt it using AES-GCM
                // and the key that Bob shares with the public-space
                // Compare the computed digest and the received digest and print the string
                // "data valid" if the verification succeeds, otherwise print "data invalid"
                final byte[] data = receive("alice");
                final byte[] computedDigest = MessageDigest.getInstance("SHA-256").digest(data);
                final byte[] iv = receive("public-space");
                final byte[] ct = receive("public-space");
                final Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding");
                decrypt.init(Cipher.DECRYPT_MODE, bobKey, new GCMParameterSpec(128, iv));
                final byte[] receivedDigest = decrypt.doFinal(ct);
                if (MessageDigest.isEqual(computedDigest, receivedDigest)) {
                    print("data valid");
                } else {
                    print("data invalid");
                }
            }
        });

        env.connect("alice", "bob");
        env.connect("alice", "public-space");
        env.connect("public-space", "bob");
        env.start();
    }
}
