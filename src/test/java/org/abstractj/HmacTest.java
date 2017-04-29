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

import org.abstractj.util.Hex;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.abstractj.fixture.TestVectors.HMAC_SHA256;
import static org.abstractj.fixture.TestVectors.HMAC_SHARED_SECRET;
import static org.abstractj.fixture.TestVectors.MESSAGE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

/**
 * @author <a href="mailto:bruno@abstractj.org">Bruno Oliveira</a>
 */
public class HmacTest {

    private static final String ALGORITHM = "HmacSHA256";
    private Mac hmac;

    @Before
    public void setup() {
        configureHmac(HMAC_SHARED_SECRET.getBytes());
    }

    private Mac configureHmac(byte[] key) {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM);
        try {
            hmac = Mac.getInstance(ALGORITHM);
            hmac.init(secretKeySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return hmac;
    }

    @Test
    public void testHmacWithValidSharedSecret() {
        byte[] result = hmac.doFinal(MESSAGE.getBytes());
        assertEquals("HMAC should be the same", HMAC_SHA256, Hex.encode(result));
    }

    @Test
    public void testHmacWithInvalidSharedSecret() {
        hmac = configureHmac("dummy secret".getBytes());
        byte[] result = hmac.doFinal(MESSAGE.getBytes());
        assertNotEquals("HMAC should be different for a new key",
                HMAC_SHA256, Hex.encode(result));
    }
}
