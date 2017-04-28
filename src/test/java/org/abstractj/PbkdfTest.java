package org.abstractj;

import org.junit.Before;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

import static org.abstractj.fixture.TestVectors.MESSAGE;
import static org.abstractj.fixture.TestVectors.PBKDF_PASSWORD;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * @author <a href="mailto:bruno@abstractj.org">Bruno Oliveira</a>
 */
public class PbkdfTest {

    private byte[] salt;
    private SecretKeySpec secretKeySpec;

    @Before
    public void setup() throws Exception {
        this.secretKeySpec = createSecretKeySpec(PBKDF_PASSWORD);
    }

    private byte[] getRandomBytes(int length) throws NoSuchAlgorithmException {
        byte[] nonce = new byte[length];
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        secureRandom.nextBytes(nonce);
        return nonce;
    }

    private SecretKeySpec createSecretKeySpec(String password) throws Exception {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        salt = getRandomBytes(16);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 20000, 128);
        SecretKey secretKey = keyFactory.generateSecret(spec);
        secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");

        return secretKeySpec;
    }

    @Test
    public void testPbkdf2WithCorrectPassword() throws Exception {
        byte[] nonce = getRandomBytes(12);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(16 * 8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, spec);
        byte[] ciphertext = cipher.doFinal(MESSAGE.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, spec);
        byte[] plaintext = cipher.doFinal(ciphertext);
        assertEquals(new String(plaintext), MESSAGE);
    }

    @Test
    public void testPbkdf2WithIncorrectPassword() throws Exception {
        byte[] nonce = getRandomBytes(12);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(16 * 8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, spec);
        byte[] ciphertext = cipher.doFinal(MESSAGE.getBytes());

        SecretKeySpec invalidKey = createSecretKeySpec("dummy-password");

        cipher.init(Cipher.DECRYPT_MODE, invalidKey, spec);
        try {
            cipher.doFinal(ciphertext);
        } catch (Exception e) {
            assertTrue(true);
        }
    }
}
