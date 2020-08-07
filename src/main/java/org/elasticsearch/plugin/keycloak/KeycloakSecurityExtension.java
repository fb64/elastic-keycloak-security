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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.plugin.keycloak.realm.KeycloakRealm;
import org.elasticsearch.xpack.core.security.SecurityExtension;
import org.elasticsearch.xpack.core.security.authc.Realm;

import java.lang.reflect.ReflectPermission;
import java.net.SocketPermission;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Collections;
import java.util.Map;

public class KeycloakSecurityExtension implements SecurityExtension {
    protected final Logger logger = LogManager.getLogger(this.getClass());
    static {
        AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
            System.getSecurityManager().checkPermission(new ReflectPermission("suppressAccessChecks"));
            System.getSecurityManager().checkPermission(new RuntimePermission("getClassLoader"));
            System.getSecurityManager().checkPermission(new SocketPermission("*","resolve,connect"));
            return null;
        });
    }

   @Override
    public Map<String, Realm.Factory> getRealms(SecurityComponents components) {
        logger.trace("Get realms for keycloak security extension");
        return Collections.singletonMap(KeycloakRealm.REALM_TYPE, KeycloakRealm::new);
    }
}
