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
