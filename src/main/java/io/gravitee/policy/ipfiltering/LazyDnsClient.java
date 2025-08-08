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

import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.node.api.configuration.Configuration;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.dns.DnsClient;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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
            dnsConfiguration.getDnsClientOptions().setRecursionDesired(true);
            dnsClient = context.getComponent(Vertx.class).createDnsClient(dnsConfiguration.getDnsClientOptions());
        }

        return dnsClient;
    }

    public static void lookup(
        ExecutionContext executionContext,
        LookupIpVersion lookupIpVersion,
        String host,
        Handler<AsyncResult<List<String>>> handler
    ) {
        DnsClient client = get(executionContext);

        switch (lookupIpVersion) {
            case IPV6:
                client.resolveAAAA(host).onComplete(handler);
                break;
            case IPV4:
                client.resolveA(host).onComplete(handler);
                break;
            case ALL:
            default:
                client
                    .resolveA(host)
                    .recover(err -> Future.succeededFuture(Collections.emptyList()))
                    .compose(ipv4List -> {
                        if (!ipv4List.isEmpty()) {
                            // Return IPv4 only
                            return Future.succeededFuture(ipv4List);
                        } else {
                            // Try IPv6 instead
                            return client.resolveAAAA(host).recover(err -> Future.succeededFuture(Collections.emptyList()));
                        }
                    })
                    .onSuccess(ipList -> handler.handle(Future.succeededFuture(ipList)))
                    .onFailure(err -> handler.handle(Future.failedFuture(err)));

                break;
        }
    }
}
