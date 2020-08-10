/*
 *  (C) Copyright 2018 Florian Bernard.
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.elasticsearch.plugin.keycloak.realm;

import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.xpack.core.security.authc.support.UsernamePasswordToken;
import org.junit.Assert;

import java.io.IOException;

public class BearerTokenTests extends ESTestCase {

    private static final String TOKEN_VALUE="testToken";

    public void testExtractToken() throws IOException {
        Settings settings = Settings.builder()
                .put(ThreadContext.PREFIX + "." + UsernamePasswordToken.BASIC_AUTH_HEADER,"Bearer "+TOKEN_VALUE)
                .build();

        ThreadContext threadContext = new ThreadContext(settings);
        SecureString credential = (SecureString)BearerToken.extractToken(threadContext, null).credentials();
        Assert.assertEquals(TOKEN_VALUE,credential.toString());
    }
}
