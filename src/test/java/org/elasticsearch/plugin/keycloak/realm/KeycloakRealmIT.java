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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.elasticsearch.client.Request;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.Response;
import org.elasticsearch.client.ResponseException;
import org.elasticsearch.common.network.NetworkModule;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.xpack.core.XPackClientPlugin;
import org.elasticsearch.xpack.core.security.authc.support.UsernamePasswordToken;
import org.keycloak.representations.AccessTokenResponse;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.core.Is.is;

public class KeycloakRealmIT extends ESIntegTestCase {

    private String getToken(){
        HttpClient client = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost("http://localhost:8080/auth/realms/elastic/protocol/openid-connect/token");
        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("grant_type", "password"));
        params.add(new BasicNameValuePair("username", "plugin-test-user"));
        params.add(new BasicNameValuePair("password", "password"));
        params.add(new BasicNameValuePair("client_secret", "7081cf27-196c-408d-b362-858a1d000b2b"));
        params.add(new BasicNameValuePair("client_id", "elastic-plugin-test"));
        try {
            httpPost.setEntity(new UrlEncodedFormEntity(params));
            HttpResponse response = client.execute(httpPost);
            ObjectMapper objectMapper = new ObjectMapper();
            AccessTokenResponse tokenResponse = objectMapper.readValue(response.getEntity().getContent(),AccessTokenResponse.class);
            return tokenResponse.getToken();
        }catch (Exception e){
            return null;
        }
    }


    @Override
    protected Settings externalClusterClientSettings() {
        return Settings.builder()
                .put(ThreadContext.PREFIX + "." + UsernamePasswordToken.BASIC_AUTH_HEADER,"Bearer "+getToken())
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
            Request request = new Request("GET", "/");

            RequestOptions.Builder optionsBuilder = request.getOptions().toBuilder();
            optionsBuilder.addHeader("Authorization","Bearer "+getToken());
            request.setOptions(optionsBuilder)
            ;
            Response response = getRestClient().performRequest(request);
            assertThat(response.getStatusLine().getStatusCode(), is(200));
        }catch (Exception e){
            fail("request should have succeed: "+e.getLocalizedMessage());
        }
    }
}
