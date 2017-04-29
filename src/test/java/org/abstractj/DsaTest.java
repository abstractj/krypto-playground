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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import static org.abstractj.fixture.TestVectors.MESSAGE;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * @author <a href="mailto:bruno@abstractj.org">Bruno Oliveira</a>
 */
public class DsaTest {

    private PublicKey publicKey;
    private PrivateKey secretKey;

    @Before
    public void setup() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(2048);
        KeyPair aliceKeyPair = keyPairGenerator.generateKeyPair();

        publicKey = aliceKeyPair.getPublic();
        secretKey = aliceKeyPair.getPrivate();
    }

    @Test
    public void testDsaWithValidSignature() throws Exception {
        Signature sig = Signature.getInstance("SHA256withDSA");
        sig.initSign(secretKey);
        sig.update(MESSAGE.getBytes());
        byte[] signature = sig.sign();

        sig.initVerify(publicKey);
        sig.update(MESSAGE.getBytes());
        assertTrue("Signature should be valid", sig.verify(signature));
    }

    @Test
    public void testDsaWithInvalidSignature() throws Exception {
        Signature sig = Signature.getInstance("SHA256withDSA");
        sig.initSign(secretKey);
        sig.update(MESSAGE.getBytes());
        byte[] signature = sig.sign();
        signature[10] = ' ';
        sig.initVerify(publicKey);
        sig.update(MESSAGE.getBytes());
        assertFalse("Signature should be invalid", sig.verify(signature));
    }
}
