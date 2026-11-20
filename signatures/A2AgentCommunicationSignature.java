package isp.signatures;

import fri.isp.Agent;
import fri.isp.Environment;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

/*
 * Assuming Alice and Bob know each other's authentic public key, exchange signed messages
 * using ECDSA. Complete ten request-reply rounds: Alice sends a signed message and Bob
 * sends a signed reply in each round. Each recipient verifies the signature and rejects
 * invalid messages. Signatures provide integrity and evidence of the signer, not secrecy.
 */
public class A2AgentCommunicationSignature {
    public static void main(String[] args) throws Exception {
        final Environment env = new Environment();

        // Create key pairs
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        final KeyPair aliceKP = kpg.generateKeyPair();
        final KeyPair bobKP = kpg.generateKeyPair();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < 10; i++) {
                    final byte[] message = ("Hey Bob! Round " + (i + 1)).getBytes(StandardCharsets.UTF_8);
                    final Signature signer = Signature.getInstance("SHA256withECDSA");
                    signer.initSign(aliceKP.getPrivate());
                    signer.update(message);
                    send("bob", message);
                    send("bob", signer.sign());

                    final byte[] reply = receive("bob");
                    final byte[] signature = receive("bob");
                    final Signature verifier = Signature.getInstance("SHA256withECDSA");
                    verifier.initVerify(bobKP.getPublic());
                    verifier.update(reply);
                    if (!verifier.verify(signature)) {
                        throw new SecurityException("Invalid signature from Bob.");
                    }
                    print("Received: %s", new String(reply, StandardCharsets.UTF_8));
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for (int i = 0; i < 10; i++) {
                    final byte[] message = receive("alice");
                    final byte[] signature = receive("alice");
                    final Signature verifier = Signature.getInstance("SHA256withECDSA");
                    verifier.initVerify(aliceKP.getPublic());
                    verifier.update(message);
                    if (!verifier.verify(signature)) {
                        throw new SecurityException("Invalid signature from Alice.");
                    }
                    print("Received: %s", new String(message, StandardCharsets.UTF_8));

                    final byte[] reply = ("Hey Alice! Round " + (i + 1)).getBytes(StandardCharsets.UTF_8);
                    final Signature signer = Signature.getInstance("SHA256withECDSA");
                    signer.initSign(bobKP.getPrivate());
                    signer.update(reply);
                    send("alice", reply);
                    send("alice", signer.sign());
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
