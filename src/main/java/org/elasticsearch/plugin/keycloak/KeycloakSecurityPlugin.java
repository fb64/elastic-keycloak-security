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
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.plugin.keycloak.realm.KeycloakRealm;
import org.elasticsearch.plugins.ActionPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.xpack.core.security.authc.RealmSettings;

import java.util.ArrayList;
import java.util.List;

public class KeycloakSecurityPlugin extends Plugin implements ActionPlugin {
    protected final Logger logger = LogManager.getLogger(this.getClass());

    @Override
    public List<Setting<?>> getSettings() {
        List<Setting<?>> list = new ArrayList<>(RealmSettings.getStandardSettings(KeycloakRealm.REALM_TYPE));
        Setting.AffixSetting<?> keycloakConfig = RealmSettings.simpleString(KeycloakRealm.REALM_TYPE, "config",
                Setting.Property.NodeScope, Setting.Property.Filtered);
        list.add(keycloakConfig);

        return list;
    }

}
