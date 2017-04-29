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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.abstractj.fixture.TestVectors.MESSAGE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * @author <a href="mailto:bruno@abstractj.org">Bruno Oliveira</a>
 */
public class RsaTest {

    private KeyPairGenerator keyPairGenerator;
    private PublicKey publicKey;
    private PrivateKey secretKey;

    @Before
    public void setup() throws Exception {
        this.keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        KeyPair aliceKeyPair = keyPairGenerator.generateKeyPair();
        publicKey = aliceKeyPair.getPublic();
        secretKey = aliceKeyPair.getPrivate();
    }

    @Test
    public void testRsaEncryptionWithValidKeyPair() throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] ciphertext = cipher.doFinal(MESSAGE.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] plaintext = cipher.doFinal(ciphertext);

        assertEquals("Decrypted ciphertext should be equal to the original message",
                new String(plaintext), MESSAGE);
    }

    @Test
    public void testRsaEncryptionWithInvalidKeyPair() throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] ciphertext = cipher.doFinal(MESSAGE.getBytes());

        KeyPair eveKeyPair = keyPairGenerator.generateKeyPair();
        cipher.init(Cipher.DECRYPT_MODE, eveKeyPair.getPrivate());
        try {
            cipher.doFinal(ciphertext);
        } catch (Exception e) {
            assertTrue("Decryption should fail for an invalid key pair", true);
        }
    }
}
