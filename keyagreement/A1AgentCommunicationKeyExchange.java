package isp.keyagreement;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

/*
 * Implement the unauthenticated key exchange from the slides between Alice and Bob using
 * public-key encryption to establish a shared symmetric secret (not DH or ECDH alone).
 * Then Alice sends Bob a message encrypted with AES-GCM. Bob decrypts and displays it.
 * The public key is not authenticated, so the exchange is vulnerable to active attackers.
 */
public class A1AgentCommunicationKeyExchange {
    public static void main(String[] args) {
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("bob"));
                final PublicKey bobPK = KeyFactory.getInstance("RSA").generatePublic(keySpec);
                final Key key = KeyGenerator.getInstance("AES").generateKey();

                final Cipher rsaEnc = Cipher.getInstance("RSA/ECB/OAEPPadding");
                rsaEnc.init(Cipher.ENCRYPT_MODE, bobPK);
                send("bob", rsaEnc.doFinal(key.getEncoded()));

                final Cipher encrypt = Cipher.getInstance("AES/GCM/NoPadding");
                encrypt.init(Cipher.ENCRYPT_MODE, key);
                final byte[] ct = encrypt.doFinal("Hey Bob!".getBytes(StandardCharsets.UTF_8));
                send("bob", encrypt.getIV());
                send("bob", ct);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                final KeyPair bobKP = kpg.generateKeyPair();
                send("alice", bobKP.getPublic().getEncoded());

                final Cipher rsaDec = Cipher.getInstance("RSA/ECB/OAEPPadding");
                rsaDec.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
                final byte[] sharedSecret = rsaDec.doFinal(receive("alice"));
                final SecretKeySpec key = new SecretKeySpec(sharedSecret, "AES");

                final byte[] iv = receive("alice");
                final byte[] ct = receive("alice");
                final Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding");
                decrypt.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
                final byte[] pt = decrypt.doFinal(ct);
                print("Received: %s", new String(pt, StandardCharsets.UTF_8));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
