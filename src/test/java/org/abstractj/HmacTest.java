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
        assertEquals(HMAC_SHA256, Hex.encode(result));
    }

    @Test
    public void testHmacWithInvalidSharedSecret() {
        hmac = configureHmac("dummy secret".getBytes());
        byte[] result = hmac.doFinal(MESSAGE.getBytes());
        assertNotEquals(HMAC_SHA256, Hex.encode(result));
    }
}
