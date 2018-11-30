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

package org.elasticsearch.plugin.keycloak;


import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.keycloak.representations.AccessTokenResponse;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class KeycloakUtils {

    private static HttpClient httpClient = HttpClients.createDefault();
    private static final String KEYCLOAK_BASE_URL="http://localhost:8080";

    public static void addUser(String username,String password) throws IOException {
        String adminToken = getKeycloakAdminToken("admin","admin");
        HttpPost httpPost = new HttpPost(KEYCLOAK_BASE_URL.concat("/auth/admin/realms/elastic/users"));
        httpPost.setHeader(HttpHeaders.AUTHORIZATION,"Bearer "+adminToken);

        StringBuilder request = new StringBuilder();
        request.append("{");
        request.append("\"username\":\""+username+"\",");
        request.append("\"enabled\":true,");
        request.append("\"credentials\":[{");
        request.append("\"type\":\"password\",");
        request.append("\"value\":\""+password+"\"}]");
        request.append("}");

        httpPost.setEntity(new StringEntity(request.toString(), ContentType.APPLICATION_JSON));
        httpClient.execute(httpPost);
    }


    private static String getKeycloakAdminToken(String username,String password){
        HttpPost httpPost = new HttpPost(KEYCLOAK_BASE_URL.concat("/auth/realms/master/protocol/openid-connect/token"));
        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("grant_type", "password"));
        params.add(new BasicNameValuePair("username", username));
        params.add(new BasicNameValuePair("password", password));
        params.add(new BasicNameValuePair("client_id", "admin-cli"));
        try {
            httpPost.setEntity(new UrlEncodedFormEntity(params));
            HttpResponse response = httpClient.execute(httpPost);
            ObjectMapper objectMapper = new ObjectMapper();
            AccessTokenResponse tokenResponse = objectMapper.readValue(response.getEntity().getContent(),AccessTokenResponse.class);
            return tokenResponse.getToken();
        }catch (Exception e){
            return null;
        }
    }

    public static String getKeycloakUserToken(String username,String password){
        HttpPost httpPost = new HttpPost(KEYCLOAK_BASE_URL.concat("/auth/realms/elastic/protocol/openid-connect/token"));
        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("grant_type", "password"));
        params.add(new BasicNameValuePair("username", username));
        params.add(new BasicNameValuePair("password", password));
        params.add(new BasicNameValuePair("client_id", "elastic-plugin-test"));
        try {
            httpPost.setEntity(new UrlEncodedFormEntity(params));
            HttpResponse response = httpClient.execute(httpPost);
            ObjectMapper objectMapper = new ObjectMapper();
            AccessTokenResponse tokenResponse = objectMapper.readValue(response.getEntity().getContent(),AccessTokenResponse.class);
            return tokenResponse.getToken();
        }catch (Exception e){
            return null;
        }
    }




}
