/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.configuration;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.gravitee.policy.ipfiltering.IPFilteringPolicyConfiguration;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.net.URL;

/**
 * Created by david on 25/07/2018.
 */
public class IPFilteringPolicyConfigurationTest {

        @Test
        public void testConfiguration_previousConfVersion() throws IOException {
            IPFilteringPolicyConfiguration configuration =
                    load("/io/gravitee/policy/ipfiltering/configuration1.json");

            Assert.assertEquals(1, configuration.getBlacklistIpList().size());
            Assert.assertEquals(1, configuration.getWhitelistIpList().size());
            Assert.assertNull(configuration.getBlacklistIpList().get(0).getInfo());
            Assert.assertNull(configuration.getWhitelistIpList().get(0).getInfo());
        }

        @Test
        public void testConfiguration_newConfVersion() throws IOException {
            IPFilteringPolicyConfiguration configuration =
                    load("/io/gravitee/policy/ipfiltering/configuration2.json");

            Assert.assertEquals(2, configuration.getBlacklistIpList().size());
            Assert.assertEquals(2, configuration.getWhitelistIpList().size());
            Assert.assertEquals("TBD", configuration.getBlacklistIpList().get(0).getInfo());
            Assert.assertEquals("TBD", configuration.getWhitelistIpList().get(0).getInfo());
        }

        private IPFilteringPolicyConfiguration load(String resource) throws IOException {
            URL jsonFile = this.getClass().getResource(resource);
            return objectMapper().readValue(jsonFile, IPFilteringPolicyConfiguration.class);
        }

        private ObjectMapper objectMapper() {
            return new ObjectMapper();
        }
}
