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

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.plugin.keycloak.exception.KeycloakConfigException;
import org.elasticsearch.xpack.core.security.authc.AuthenticationResult;
import org.elasticsearch.xpack.core.security.authc.AuthenticationToken;
import org.elasticsearch.xpack.core.security.authc.Realm;
import org.elasticsearch.xpack.core.security.authc.RealmConfig;
import org.elasticsearch.xpack.core.security.authc.RealmSettings;
import org.elasticsearch.xpack.core.security.user.User;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.representations.AccessToken;

import java.io.IOException;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Set;

public class KeycloakRealm extends Realm {
    public static final String REALM_TYPE = "keycloak";
    public static final String CONFIG_KEY = "config";
    private final KeycloakDeployment keycloakDeployment;

    public KeycloakRealm(RealmConfig config) {
        super(config);  //NOTE: removed REALM_TYPE from constructor
        String pathString = config.getSetting(RealmSettings.simpleString(KeycloakRealm.REALM_TYPE,
                CONFIG_KEY, Setting.Property.NodeScope, Setting.Property.Filtered));
        Path configPath = getConfigPath(pathString);
        try(FileChannel channel =FileChannel.open(configPath, StandardOpenOption.READ)) {
            keycloakDeployment = AccessController.doPrivileged(
                    (PrivilegedAction<KeycloakDeployment>) () ->  KeycloakDeploymentBuilder.build(Channels.newInputStream(channel)));
        }  catch (IOException e) {
            throw new KeycloakConfigException("Unable to load keycloak config file : "+pathString,e);
        }
        logger.info("Loaded keycloak config file");
    }

    private Path getConfigPath(String configFilePath){
        Path configPath;
        try {
            configPath = config.env().configFile().resolve(configFilePath);
        }catch (InvalidPathException e){
            configPath = null;
        }
        return configPath;
    }

    @Override
    public boolean supports(AuthenticationToken authenticationToken) {
        logger.trace("Checking support for Keycloak token");
        return authenticationToken instanceof BearerToken;
    }

    @Override
    public AuthenticationToken token(ThreadContext threadContext) {
        logger.trace("Building Authentication Token in Keycloak Realm");
        return BearerToken.extractToken(threadContext, keycloakDeployment);
    }

    @Override
    public void authenticate(AuthenticationToken authenticationToken, ActionListener<AuthenticationResult> actionListener) {
        logger.trace("Authenticating token for Keycloak");
        //Ensure correct authentication token
        if (!(authenticationToken instanceof BearerToken)) throw new AssertionError();
        BearerToken bearerToken = (BearerToken) authenticationToken;
        AccessToken accessToken = bearerToken.keycloakAccessToken();

        if(accessToken != null){
            Set<String> roles = accessToken.getRealmAccess().getRoles();
            User user = new User(accessToken.getPreferredUsername(),roles.toArray(new String[0]));
            actionListener.onResponse(AuthenticationResult.success(user));
        }else{
            actionListener.onFailure(new NullPointerException("Token: " + authenticationToken.credentials()));
        }
    }

    @Override
    public void lookupUser(String s, ActionListener<User> actionListener) {
        actionListener.onResponse(null);
    }
}
