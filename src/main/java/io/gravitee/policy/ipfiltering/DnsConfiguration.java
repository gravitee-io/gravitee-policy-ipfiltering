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

import io.gravitee.node.api.configuration.Configuration;
import io.vertx.core.dns.DnsClientOptions;

/**
 * DnsConfiguration is a class that provides a DNS configuration.
 * The DNS configuration is retrieved from the global configuration of the gateway.
 */
public class DnsConfiguration {

    private static final String SYSTEM_DNS_PREFIX = "policy.ip-filtering.dns.";
    private static final String DNS_HOST = SYSTEM_DNS_PREFIX + "host";
    private static final String DNS_PORT = SYSTEM_DNS_PREFIX + "port";

    private final String dnsServerHost;

    private final int dnsServerPort;

    private final boolean hasGlobalConfiguration;

    public DnsConfiguration(Configuration globalConfiguration) {
        this.dnsServerHost = globalConfiguration.getProperty(DNS_HOST, String.class);
        Integer port = globalConfiguration.getProperty(DNS_PORT, Integer.class);
        this.dnsServerPort = (port != null) ? port : -1;
        hasGlobalConfiguration = dnsServerHost != null && dnsServerPort != -1;
    }

    public DnsClientOptions getDnsClientOptions() {
        DnsClientOptions dnsClientOptions = new DnsClientOptions();
        if (hasGlobalConfiguration) {
            dnsClientOptions.setHost(dnsServerHost);
            dnsClientOptions.setPort(dnsServerPort);
        }
        return dnsClientOptions;
    }
}
