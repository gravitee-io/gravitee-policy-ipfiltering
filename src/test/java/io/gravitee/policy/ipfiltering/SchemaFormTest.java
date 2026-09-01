/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.ipfiltering;

import static org.assertj.core.api.Assertions.assertThat;

import io.gravitee.json.validation.JsonSchemaValidator;
import io.gravitee.json.validation.JsonSchemaValidatorImpl;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;
import org.junit.Test;

public class SchemaFormTest {

    private final JsonSchemaValidator jsonSchemaValidator = new JsonSchemaValidatorImpl();

    private final String schema = loadSchema();

    @Test
    public void shouldApplyUseCustomIPAddressDefaultWhenNotStored() {
        // A configuration saved with only a whitelist entry does not store useCustomIPAddress.
        // The console hides the X-Forwarded-For option unless the value is actually present,
        // so the schema has to supply it.
        JSONObject validated = new JSONObject(
            jsonSchemaValidator.validate(schema, "{\"lookupIpVersion\":\"ALL\",\"whitelistIps\":[\"203.0.113.4\"]}")
        );

        assertThat(validated.has("useCustomIPAddress")).as("useCustomIPAddress is populated from its default").isTrue();
        assertThat(validated.getBoolean("useCustomIPAddress")).isFalse();
    }

    @Test
    public void shouldApplyUseCustomIPAddressDefaultOnEmptyConfiguration() {
        JSONObject validated = new JSONObject(jsonSchemaValidator.validate(schema, "{}"));

        assertThat(validated.has("useCustomIPAddress")).as("useCustomIPAddress is populated from its default").isTrue();
        assertThat(validated.getBoolean("useCustomIPAddress")).isFalse();
    }

    @Test
    public void shouldKeepUseCustomIPAddressWhenExplicitlyEnabled() {
        JSONObject validated = new JSONObject(
            jsonSchemaValidator.validate(schema, "{\"useCustomIPAddress\":true,\"customIPAddress\":\"203.0.113.4\"}")
        );

        assertThat(validated.getBoolean("useCustomIPAddress")).isTrue();
    }

    private String loadSchema() {
        try (InputStream in = getClass().getResourceAsStream("/schemas/schema-form.json")) {
            if (in == null) {
                throw new IllegalStateException("Unable to find /schemas/schema-form.json");
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
