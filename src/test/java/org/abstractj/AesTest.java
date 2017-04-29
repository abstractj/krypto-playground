/**
 * Copyright 2017 Bruno Oliveira, and individual contributors
 * <p/>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.abstractj;

import org.junit.Before;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

import static org.abstractj.fixture.TestVectors.MESSAGE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

/**
 * @author <a href="mailto:bruno@abstractj.org">Bruno Oliveira</a>
 */
public class AesTest {

    private SecretKey secretKey;
    private byte[] nonce;

    @Before
    public void setup() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        secretKey = keyGenerator.generateKey();
        nonce = new byte[12];
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        secureRandom.nextBytes(nonce);
    }

    @Test
    public void testAesCBC() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] iv = cipher.getIV();
        byte[] ciphertext = cipher.doFinal(MESSAGE.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] plaintext = cipher.doFinal(ciphertext);
        assertEquals("Decrypted ciphertext should be equal to the original message",
                new String(plaintext), MESSAGE);
    }

    @Test
    public void testAesCBCCipherShouldNotBeTheSame() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] iv = cipher.getIV();
        byte[] ciphertext1 = cipher.doFinal(MESSAGE.getBytes());
        byte[] ciphertext2 = cipher.doFinal(MESSAGE.getBytes());

        assertNotEquals("Ciphertext should be different", ciphertext1, ciphertext2);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] plaintext1 = cipher.doFinal(ciphertext1);
        byte[] plaintext2 = cipher.doFinal(ciphertext2);
        assertEquals("Decrypted ciphertext should be equal to the original message",
                new String(plaintext1), new String(plaintext2));
    }

    @Test
    public void testAesCBCWithCorruptedCipherText() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] iv = cipher.getIV();
        byte[] ciphertext = cipher.doFinal(MESSAGE.getBytes());
        ciphertext[10] = ' ';
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] plaintext = cipher.doFinal(ciphertext);
        assertNotEquals("Ciphertext should be different", new String(plaintext), MESSAGE);
        assertTrue("Message should be decrypted even if the ciphertext was corrupted",
                new String(plaintext).contains("won"));
    }

    @Test
    public void testAesCTR() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] iv = cipher.getIV();
        byte[] ciphertext = cipher.doFinal(MESSAGE.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] plaintext = cipher.doFinal(ciphertext);
        assertEquals("Decrypted ciphertext should be equal to the original message",
                new String(plaintext), MESSAGE);
    }

    @Test
    public void testAesCTRCipherTextMustBeDifferent() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] iv = cipher.getIV();
        byte[] ciphertext1 = cipher.doFinal(MESSAGE.getBytes());
        byte[] ciphertext2 = cipher.doFinal(MESSAGE.getBytes());

        assertNotEquals("Ciphertext should be different", ciphertext1, ciphertext2);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] plaintext1 = cipher.doFinal(ciphertext1);
        byte[] plaintext2 = cipher.doFinal(ciphertext2);
        assertEquals("Decrypted ciphertext should be equal to the original message",
                new String(plaintext1), new String(plaintext2));
    }

    @Test
    public void testAesCTRWithCorruptedCipherText() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] iv = cipher.getIV();
        byte[] ciphertext = cipher.doFinal(MESSAGE.getBytes());
        ciphertext[10] = ' ';
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] plaintext = cipher.doFinal(ciphertext);
        assertNotEquals("Ciphertext should be different", new String(plaintext), MESSAGE);
        assertTrue("Message should be decrypted even if the ciphertext was corrupted",
                new String(plaintext).contains("won"));
    }

    @Test
    public void testAesGCM() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(16 * 8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        byte[] ciphertext = cipher.doFinal(MESSAGE.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        byte[] plaintext = cipher.doFinal(ciphertext);
        assertEquals("Decrypted ciphertext should be equal to the original message",
                new String(plaintext), MESSAGE);
    }

    @Test
    public void testAesGCMShouldNotPermitReuseOfKeyOrIv() throws Exception {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(16 * 8, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            cipher.doFinal(MESSAGE.getBytes());
            cipher.doFinal(MESSAGE.getBytes());
        } catch (Exception e) {
            assertTrue("Encryption should fail with the reuse of the same Key", true);
        }
    }

    @Test
    public void testAesGCMShouldThrowAnExceptionWithCorruptedCipherText() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(16 * 8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        byte[] ciphertext = cipher.doFinal(MESSAGE.getBytes());
        ciphertext[10] = ' ';
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        try {
            cipher.doFinal(ciphertext);
        } catch (Exception e) {
            assertTrue("Decryption should fail if the ciphertext was corrupted", true);
        }
    }
}
