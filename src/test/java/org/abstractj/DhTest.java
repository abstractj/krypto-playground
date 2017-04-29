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
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import static org.abstractj.fixture.TestVectors.MESSAGE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * @author <a href="mailto:bruno@abstractj.org">Bruno Oliveira</a>
 */
public class DhTest {

    private KeyAgreement aliceKeyAgreement;
    private KeyPair keyPairAlice;
    private KeyAgreement bobKeyAgreement;
    private KeyPairGenerator keyPairGenerator;

    @Before
    public void setup() throws Exception {
        AlgorithmParameterGenerator parameterGenerator = AlgorithmParameterGenerator.getInstance("DH");
        parameterGenerator.init(512);
        AlgorithmParameters algorithmParameters = parameterGenerator.generateParameters();

        DHParameterSpec dhParameterSpec = algorithmParameters.getParameterSpec(DHParameterSpec.class);

        keyPairGenerator = KeyPairGenerator.getInstance("DH");
        keyPairGenerator.initialize(dhParameterSpec);

        keyPairAlice = keyPairGenerator.generateKeyPair();
        KeyPair keyPairBob = keyPairGenerator.generateKeyPair();

        aliceKeyAgreement = KeyAgreement.getInstance("DH");
        bobKeyAgreement = KeyAgreement.getInstance("DH");

        aliceKeyAgreement.init(keyPairAlice.getPrivate());
        bobKeyAgreement.init(keyPairBob.getPrivate());

        aliceKeyAgreement.doPhase(keyPairBob.getPublic(), true);
        bobKeyAgreement.doPhase(keyPairAlice.getPublic(), true);
    }

    @Test
    public void testDhEncryptionWithValidKeyAgreement() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        final byte[] nonce = new byte[12];
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        secureRandom.nextBytes(nonce);

        GCMParameterSpec spec = new GCMParameterSpec(16 * 8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, aliceKeyAgreement.generateSecret("AES"), spec);
        byte[] ciphertext = cipher.doFinal(MESSAGE.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, bobKeyAgreement.generateSecret("AES"), spec);
        byte[] plaintext = cipher.doFinal(ciphertext);
        assertEquals("Decrypted ciphertext should be equal to the original message", new String(plaintext), MESSAGE);
    }

    @Test
    public void testDhEncryptionWithValidKeyAgreementAndCorruptedCiphertext() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        final byte[] nonce = new byte[12];
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        secureRandom.nextBytes(nonce);

        GCMParameterSpec spec = new GCMParameterSpec(16 * 8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, aliceKeyAgreement.generateSecret("AES"), spec);
        byte[] ciphertext = cipher.doFinal(MESSAGE.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, bobKeyAgreement.generateSecret("AES"), spec);
        ciphertext[10] = ' ';
        try {
            cipher.doFinal(ciphertext);
        } catch (Exception e) {
            assertTrue("Decryption should fail when corrupted ciphertext is provided", true);
        }
    }

    @Test
    public void testDhEncryptionWithInvalidKeyAgreement() throws Exception {
        KeyPair keyPairEve = keyPairGenerator.generateKeyPair();
        KeyAgreement eveKeyAgreement = KeyAgreement.getInstance("DH");
        eveKeyAgreement.init(keyPairEve.getPrivate());
        eveKeyAgreement.doPhase(keyPairAlice.getPublic(), true);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        final byte[] nonce = new byte[12];
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        secureRandom.nextBytes(nonce);

        GCMParameterSpec spec = new GCMParameterSpec(16 * 8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, aliceKeyAgreement.generateSecret("AES"), spec);
        byte[] ciphertext = cipher.doFinal(MESSAGE.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, eveKeyAgreement.generateSecret("AES"), spec);
        try {
            cipher.doFinal(ciphertext);
        } catch (Exception e) {
            assertTrue("Decryption should fail with invalid key agreement", true);
        }
    }
}
