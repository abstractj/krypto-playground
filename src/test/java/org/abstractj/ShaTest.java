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
        assertEquals(MESSAGE_SHA256, Hex.encode(digest));
    }

    @Test
    public void testInvalidHash() {
        byte[] digest = messageDigest.digest(MESSAGE.getBytes());
        digest[6] = ' ';
        assertNotEquals(MESSAGE_SHA256, Hex.encode(digest));
    }
}
