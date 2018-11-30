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

import org.elasticsearch.client.Request;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.Response;
import org.elasticsearch.client.ResponseException;
import org.elasticsearch.common.network.NetworkModule;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.plugin.keycloak.KeycloakUtils;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.xpack.core.XPackClientPlugin;
import org.elasticsearch.xpack.core.security.authc.support.UsernamePasswordToken;
import org.junit.BeforeClass;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;

import static org.hamcrest.core.Is.is;

public class KeycloakRealmIT extends ESIntegTestCase {

    private static final String TEST_USER="plugin-test-user";
    private static final String TEST_PASSWORD="password";

    @BeforeClass
    public static void initTestUser() throws IOException {
        KeycloakUtils.addUser(TEST_USER,TEST_PASSWORD);
    }

    @Override
    protected Settings externalClusterClientSettings() {
        String userToken = KeycloakUtils.getKeycloakUserToken(TEST_USER,TEST_PASSWORD);
        return Settings.builder()
                .put(ThreadContext.PREFIX + "." + UsernamePasswordToken.BASIC_AUTH_HEADER,"Bearer "+userToken)
                .put(NetworkModule.TRANSPORT_TYPE_KEY, "security4")
                .build();
    }


    @Override
    protected Collection<Class<? extends Plugin>> transportClientPlugins() {
        return Collections.singleton(XPackClientPlugin.class);
    }

    public void testBadToken() throws Exception{
        try {
            getRestClient().performRequest(new Request("GET", "/"));
            fail("request should have failed");
        } catch(ResponseException e) {
            Response response = e.getResponse();
            assertThat(response.getStatusLine().getStatusCode(), is(401));
        }
    }

    public void testValidToken() {
        try {
            String userToken = KeycloakUtils.getKeycloakUserToken(TEST_USER,TEST_PASSWORD);
            Request request = new Request("GET", "/");
            RequestOptions.Builder optionsBuilder = request.getOptions().toBuilder();
            optionsBuilder.addHeader("Authorization","Bearer "+userToken);
            request.setOptions(optionsBuilder)
            ;
            Response response = getRestClient().performRequest(request);
            assertThat(response.getStatusLine().getStatusCode(), is(200));
        }catch (Exception e){
            fail("request should have succeed: "+e.getLocalizedMessage());
        }
    }
}
