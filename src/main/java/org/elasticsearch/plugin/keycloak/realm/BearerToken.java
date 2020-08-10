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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.xpack.core.security.authc.AuthenticationToken;
import org.elasticsearch.xpack.core.security.support.Exceptions;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.rotation.AdapterTokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.AccessController;
import java.security.PrivilegedAction;

public class BearerToken implements AuthenticationToken {
    protected final Logger logger = LogManager.getLogger(this.getClass());
    public static final String BEARER_AUTH_PREFIX = "Bearer ";
    public static final String BEARER_AUTH_HEADER = "Authorization";

    private final SecureString accessToken;
    private final String principal;
    private final AccessToken keycloakAccessToken;

    public BearerToken(SecureString accessToken, String username, AccessToken keycloakToken){
        this.accessToken = accessToken;
        keycloakAccessToken = keycloakToken;
        principal = username == null ? "" : username;
    }

    public AccessToken keycloakAccessToken(){
        return keycloakAccessToken;
    }

    @Override
    public String principal() {
        return principal;
    }

    @Override
    public Object credentials() {
        return accessToken;
    }

    @Override
    public void clearCredentials() {
        accessToken.close();
    }


    public static BearerToken extractToken(ThreadContext context, KeycloakDeployment keycloakDeployment) {
        String authStr = context.getHeader(BEARER_AUTH_HEADER);
        return authStr == null ? null : extractToken(authStr, keycloakDeployment);
    }

    private static BearerToken extractToken(String headerValue, KeycloakDeployment keycloakDeployment) {
        if (!headerValue.startsWith(BEARER_AUTH_PREFIX)) {
            return null;
        } else if (headerValue.length() == BEARER_AUTH_PREFIX.length()) {
            throw Exceptions.authenticationError("Invalid Bearer authentication header value");
        } else {
            String tokenValue = headerValue.substring(BEARER_AUTH_PREFIX.length()).trim();
            String tokenValueString = new String(tokenValue.getBytes(Charset.defaultCharset()), StandardCharsets.UTF_8);
            String username = null;
            AccessToken keycloakToken = null;
            if(keycloakDeployment != null){
                keycloakToken = AccessController.doPrivileged(
                        (PrivilegedAction<AccessToken>) () -> {
                            try {
                                return AdapterTokenVerifier.verifyToken(tokenValueString, keycloakDeployment);
                            } catch (VerificationException e) {
                                throw Exceptions.authenticationError("Failed to authenticate token");
                            }
                        });
                username = keycloakToken.getPreferredUsername();
            }
            return new BearerToken(new SecureString(tokenValueString.toCharArray()), username, keycloakToken);
        }
    }
}
