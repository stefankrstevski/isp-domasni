package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, secure the channel using
 * AES in GCM mode. Complete ten request-reply rounds: Alice sends one
 * encrypted message and Bob sends one encrypted reply in each round (twenty
 * encrypted messages in total). Both agents must decrypt and display the
 * messages they receive. Use a fresh IV for every encryption and send it
 * together with the ciphertext; the IV need not be secret.
 * <p>
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Cipher.html
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/spec/GCMParameterSpec.html
 */
public class A1AgentCommunicationGCM {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for AES in GCM.
         */
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String text = "I hope you get this message intact and in secret. Kisses, Alice.";
                for (int i = 0; i < 10; i++) {
                    final Cipher encrypt = Cipher.getInstance("AES/GCM/NoPadding");
                    encrypt.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = encrypt.doFinal(text.getBytes(StandardCharsets.UTF_8));
                    send("bob", encrypt.getIV());
                    send("bob", ct);

                    final byte[] iv = receive("bob");
                    final byte[] reply = receive("bob");
                    final Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding");
                    decrypt.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
                    final byte[] pt = decrypt.doFinal(reply);
                    print("Received: %s", new String(pt, StandardCharsets.UTF_8));
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < 10; i++) {
                    final byte[] iv = receive("alice");
                    final byte[] ct = receive("alice");
                    final Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding");
                    decrypt.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
                    final byte[] pt = decrypt.doFinal(ct);
                    print("Received: %s", new String(pt, StandardCharsets.UTF_8));

                    final String reply = "I got your message. Kisses, Bob.";
                    final Cipher encrypt = Cipher.getInstance("AES/GCM/NoPadding");
                    encrypt.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] encryptedReply = encrypt.doFinal(reply.getBytes(StandardCharsets.UTF_8));
                    send("alice", encrypt.getIV());
                    send("alice", encryptedReply);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
