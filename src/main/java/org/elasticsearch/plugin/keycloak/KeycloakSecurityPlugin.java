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

import org.elasticsearch.plugin.keycloak.realm.BearerToken;
import org.elasticsearch.plugins.ActionPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.rest.RestHeaderDefinition;

import java.util.Collection;
import java.util.Collections;

public class KeycloakSecurityPlugin extends Plugin implements ActionPlugin {
    @Override
    public Collection<RestHeaderDefinition> getRestHeaders() {
        return Collections.singletonList(new RestHeaderDefinition(BearerToken.BEARER_AUTH_HEADER, false));
    }
}
