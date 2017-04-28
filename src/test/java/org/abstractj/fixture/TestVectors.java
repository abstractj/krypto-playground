package org.abstractj.fixture;

/**
 * @author <a href="mailto:bruno@abstractj.org">Bruno Oliveira</a>
 */
public interface TestVectors {

    String MESSAGE = "I fought the law and the law won";
    String MESSAGE_SHA256 = "96603e498035ab807c77e9ef1a4e0dee1cbaa070b9e9a7566609bc334cd76e8a";

    String HMAC_SHARED_SECRET = "my super secret";
    String HMAC_SHA256 = "4b3e36b7c1fa14c40e3eb0b7b27135a86f92c7410d63cd3cc26a12fbd5c70c6d";

    String PBKDF_PASSWORD = "super-secret";
}
