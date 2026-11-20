package isp.secrecy;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Implement a brute force key search (exhaustive key search) if you know that the
 * message is:
 * "I would like to keep this text confidential Bob. Kind regards, Alice."
 * <p>
 * Assume the message was encrypted with "DES/ECB/PKCS5Padding".
 * Also assume that the key was poorly chosen. In particular, as an attacker,
 * you are certain that all bytes in the key, with the exception of the last three bytes,
 * have been set to 0.
 * <p>
 * A DES key is represented by 8 bytes, but only 56 bits affect encryption; the remaining
 * bits are parity bits. Varying the last three bytes produces 2^24 byte representations
 * but only 2^21 effective keys. Any equivalent key that correctly decrypts the ciphertext
 * is acceptable; it need not match the original key byte for byte.
 * <p>
 * In main(), generate a demonstration key with the stated restriction, encrypt the supplied
 * message with DES/ECB/PKCS5Padding, and call bruteForceKey(). Verify that the returned key
 * decrypts the ciphertext to the complete original message. Use UTF-8 for text conversion.
 * The search must use only its arguments and the stated key restriction, not the original key.
 * DES and ECB are used only for this teaching exercise, not as recommended encryption.
 * <p>
 * To manually specify a key, use {@link javax.crypto.spec.SecretKeySpec}.
 */
public class A4ExhaustiveSearch {
    public static void main(String[] args) throws Exception {
        final String message = "I would like to keep this text confidential Bob. Kind regards, Alice.";
        System.out.println("[MESSAGE] " + message);

        final byte[] key = new byte[8];
        new SecureRandom().nextBytes(key);
        for (int i = 0; i < 5; i++) {
            key[i] = 0;
        }

        final Cipher encrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");
        encrypt.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
        final byte[] ct = encrypt.doFinal(message.getBytes(StandardCharsets.UTF_8));
        final byte[] foundKey = bruteForceKey(ct, message);

        if (foundKey == null) {
            System.out.println("Key not found.");
        } else {
            final Cipher decrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");
            decrypt.init(Cipher.DECRYPT_MODE, new SecretKeySpec(foundKey, "DES"));
            final String decrypted = new String(decrypt.doFinal(ct), StandardCharsets.UTF_8);
            System.out.println("[KEY] " + Arrays.toString(foundKey));
            System.out.println("[DECRYPTED] " + decrypted);
            System.out.println("Matches original: " + message.equals(decrypted));
        }
    }

    /**
     * Recover an 8-byte representation of a key that decrypts ct to the known message.
     * Return null if no matching key exists within the restricted search space.
     */
    public static byte[] bruteForceKey(byte[] ct, String message) throws Exception {
        final byte[] key = new byte[8];
        final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
        final Cipher encrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");

        // The lowest bit of each DES key byte is a parity bit, so skip it.
        for (int a = 0; a < 256; a += 2) {
            key[5] = (byte) a;
            for (int b = 0; b < 256; b += 2) {
                key[6] = (byte) b;
                for (int c = 0; c < 256; c += 2) {
                    key[7] = (byte) c;
                    encrypt.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
                    // A correct key produces the same ciphertext for the known message.
                    if (Arrays.equals(ct, encrypt.doFinal(pt))) {
                        return key;
                    }
                }
            }
        }

        return null;
    }
}
