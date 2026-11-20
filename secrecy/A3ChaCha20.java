package isp.secrecy;

import java.security.Key;

import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;
import java.nio.charset.StandardCharsets;

import fri.isp.Agent;
import fri.isp.Environment;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, encrypt their messages
 * using the ChaCha20 stream cipher to provide confidentiality. Perform ten request-reply rounds:
 * Alice sends one encrypted message and Bob sends one encrypted reply in each round
 * (twenty encrypted messages in total). Both agents must decrypt and display received messages.
 * This exercise does not provide message authentication.
 * <p>
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Cipher.html
 * https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/spec/ChaCha20ParameterSpec.html
 */
public class A3ChaCha20 {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // Both agents can access this shared key from the enclosing method
        final Key key = KeyGenerator.getInstance("ChaCha20").generateKey();

        // STEP 2: Setup communication
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "I love you Bob. Kisses, Alice.";
                for (int i = 0; i < 10; i++) {
                    final Cipher encrypt = Cipher.getInstance("ChaCha20");
                    final byte[] nonce = new byte[12];
                    // Alice uses even nonces, Bob uses odd nonces; both use counter 0.
                    nonce[11] = (byte) (2 * i);
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 0));
                    final byte[] ct = encrypt.doFinal(message.getBytes(StandardCharsets.UTF_8));
                    send("bob", ct);
                    send("bob", encrypt.getIV());

                    final byte[] received = receive("bob");
                    final byte[] receivedNonce = receive("bob");
                    final Cipher decrypt = Cipher.getInstance("ChaCha20");
                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(receivedNonce, 0));
                    final byte[] dt = decrypt.doFinal(received);
                    print("Got '%s'", new String(dt, StandardCharsets.UTF_8));
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final String message = "I love you too Alice. Kisses, Bob.";
                for (int i = 0; i < 10; i++) {
                    final byte[] received = receive("alice");
                    final byte[] receivedNonce = receive("alice");
                    final Cipher decrypt = Cipher.getInstance("ChaCha20");
                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(receivedNonce, 0));
                    final byte[] dt = decrypt.doFinal(received);
                    print("Got '%s'", new String(dt, StandardCharsets.UTF_8));

                    final Cipher encrypt = Cipher.getInstance("ChaCha20");
                    final byte[] nonce = new byte[12];
                    // Alice uses even nonces, Bob uses odd nonces; both use counter 0.
                    nonce[11] = (byte) (2 * i + 1);
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 0));
                    final byte[] ct = encrypt.doFinal(message.getBytes(StandardCharsets.UTF_8));
                    send("alice", ct);
                    send("alice", encrypt.getIV());
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
