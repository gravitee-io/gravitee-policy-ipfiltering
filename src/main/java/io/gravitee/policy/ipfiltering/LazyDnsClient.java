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
package io.gravitee.policy.ipfiltering;

import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.node.api.configuration.Configuration;
import io.vertx.core.Vertx;
import io.vertx.core.dns.DnsClient;

/**
 * LazyDnsClient is an abstract class that provides a lazy initialization of a DNS client. The DNS client is only created when required.
 * The class provides a static method `get` to retrieve the DNS client. If the DNS client has not been created yet, it will be lazily created based on configuration done at the Gateway level.
 * Once created, the DNS client will be cached and returned for subsequent calls.
 *
 * @see DnsClient
 * @see ExecutionContext
 */
public class LazyDnsClient {

    private LazyDnsClient() {}

    private static DnsClient dnsClient;

    public static DnsClient get(ExecutionContext context) {
        if (dnsClient == null) {
            DnsConfiguration dnsConfiguration = new DnsConfiguration(context.getComponent(Configuration.class));
            dnsClient = context.getComponent(Vertx.class).createDnsClient(dnsConfiguration.getDnsClientOptions());
        }

        return dnsClient;
    }
}
