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
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.xpack.core.security.authc.AuthenticationToken;
import org.elasticsearch.xpack.core.security.authc.support.CharArrays;
import org.elasticsearch.xpack.core.security.support.Exceptions;

import java.nio.charset.Charset;

public class BearerToken implements AuthenticationToken {
    public static final String BEARER_AUTH_PREFIX = "Bearer ";
    public static final String BEARER_AUTH_HEADER = "Authorization";

    private final SecureString accessToken;

    public BearerToken(SecureString accessToken){
        this.accessToken = accessToken;
    }

    @Override
    public String principal() {
        return null;
    }

    @Override
    public Object credentials() {
        return accessToken;
    }

    @Override
    public void clearCredentials() {
        accessToken.close();
    }


    public static BearerToken extractToken(ThreadContext context) {
        String authStr = context.getHeader(BEARER_AUTH_HEADER);
        return authStr == null ? null : extractToken(authStr);
    }

    private static BearerToken extractToken(String headerValue) {
        if (!headerValue.startsWith(BEARER_AUTH_PREFIX)) {
            return null;
        } else if (headerValue.length() == BEARER_AUTH_PREFIX.length()) {
            throw Exceptions.authenticationError("invalid Bearer authentication header value");
        } else {
            String tokenValue = headerValue.substring(BEARER_AUTH_PREFIX.length()).trim();
            char[] accessToken = CharArrays.utf8BytesToChars(tokenValue.getBytes(Charset.defaultCharset()));
            return new BearerToken(new SecureString(accessToken));
        }
    }
}
