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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.abstractj.fixture.TestVectors.MESSAGE;
import static org.abstractj.fixture.TestVectors.MESSAGE_SHA256;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

/**
 * @author <a href="mailto:bruno@abstractj.org">Bruno Oliveira</a>
 */
public class ShaTest {

    private MessageDigest messageDigest;

    @Before
    public void setup() throws NoSuchAlgorithmException {
        messageDigest = MessageDigest.getInstance("SHA-256");
    }

    @Test
    public void testValidHash() {
        byte[] digest = messageDigest.digest(MESSAGE.getBytes());
        assertEquals("Hash should be the same", MESSAGE_SHA256, Hex.encode(digest));
    }

    @Test
    public void testInvalidHash() {
        byte[] digest = messageDigest.digest(MESSAGE.getBytes());
        digest[6] = ' ';
        assertNotEquals("HMAC should be the different", MESSAGE_SHA256, Hex.encode(digest));
    }
}
