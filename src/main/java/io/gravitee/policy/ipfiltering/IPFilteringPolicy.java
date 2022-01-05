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

import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.vertx.core.CompositeFuture;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.dns.DnsClient;
import org.apache.commons.net.util.SubnetUtils;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;

import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.toList;

/**
 * @author Nicolas GERAUD (nicolas.geraud at graviteesource.com)
 * @author Azize ELAMRANI (azize.elamrani at graviteesource.com)
 * @author GraviteeSource Team
 */
public class IPFilteringPolicy {

    private static final Logger LOGGER = LoggerFactory.getLogger(IPFilteringPolicy.class);

    /**
     * The associated configuration to this IPFiltering Policy
     */
    private final IPFilteringPolicyConfiguration configuration;

    // DNS client is created lazily and only if required
    private static DnsClient dnsClient;

    /**
     * Create a new IPFiltering Policy instance based on its associated configuration
     *
     * @param configuration the associated configuration to the new IPFiltering Policy instance
     */
    public IPFilteringPolicy(IPFilteringPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @OnRequest
    public void onRequest(ExecutionContext executionContext, PolicyChain policyChain) {
        final List<String> ips = extractIps(executionContext.request());
        final List<Future> futures = new ArrayList<>();

        if (configuration.getBlacklistIps() != null && !configuration.getBlacklistIps().isEmpty()) {
            final List<String> filteredIps = new ArrayList<>();
            final List<String> filteredHosts = new ArrayList<>();
            processFilteredLists(configuration.getBlacklistIps(), filteredIps, filteredHosts);
            if (!filteredIps.isEmpty() && ips.stream().anyMatch(ip -> isFiltered(ip, filteredIps))) {
                fail(policyChain, executionContext.request().remoteAddress());
                return;
            }

            if (!filteredHosts.isEmpty()) {
                DnsClient dnsClient = getDnsClient(executionContext);
                filteredHosts.forEach(host -> {
                    final Promise<Void> promise = Promise.promise();
                    futures.add(promise.future());
                    dnsClient.lookup(host, event -> {
                        if (event.succeeded()) {
                            if (executionContext.request().remoteAddress().equals(event.result())) {
                                promise.fail("");
                            } else {
                                promise.complete();
                            }
                        } else {
                            LOGGER.error("Cannot resolve host: '" + host + "'", event.cause());
                            promise.complete();
                        }
                    });
                });
            }
        }

        if (configuration.getWhitelistIps() != null && !configuration.getWhitelistIps().isEmpty()) {
            final List<String> filteredIps = new ArrayList<>();
            final List<String> filteredHosts = new ArrayList<>();
            processFilteredLists(configuration.getWhitelistIps(), filteredIps, filteredHosts);
            if (!filteredIps.isEmpty() && ips.stream().noneMatch(ip -> isFiltered(ip, filteredIps))) {
                fail(policyChain, executionContext.request().remoteAddress());
                return;
            }

            if (!filteredHosts.isEmpty()) {
                DnsClient dnsClient = getDnsClient(executionContext);
                filteredHosts.forEach(host -> {
                    final Promise<Void> promise = Promise.promise();
                    futures.add(promise.future());
                    dnsClient.lookup(host, event -> {
                        if (event.succeeded()) {
                            if (!executionContext.request().remoteAddress().equals(event.result())) {
                                promise.fail("");
                            } else {
                                promise.complete();
                            }
                        } else {
                            LOGGER.error("Cannot resolve host: '" + host + "'", event.cause());
                            promise.complete();
                        }
                    });
                });
            }
        }

        if (futures.isEmpty()) {
            policyChain.doNext(executionContext.request(), executionContext.response());
        } else {
            CompositeFuture.all(futures)
                    .onSuccess(__ -> policyChain.doNext(executionContext.request(), executionContext.response()))
                    .onFailure(__ -> fail(policyChain, executionContext.request().remoteAddress()));
        }
    }

    private void processFilteredLists(final List<String> filteredList, final List<String> filteredIps,
                                      final List<String> filteredHosts) {
        filteredList
                .stream()
                .filter(Objects::nonNull)
                .forEach(filteredItem -> {
            final int index = filteredItem.indexOf('/');
            final String filteredItemToCheck;
            if (index != -1) {
                filteredItemToCheck = filteredItem.substring(0, index);
            } else {
                filteredItemToCheck = filteredItem;
            }
            if (InetAddressValidator.getInstance().isValid(filteredItemToCheck)) {
                filteredIps.add(filteredItem);
            } else {
                filteredHosts.add(filteredItem);
            }
        });
    }

    private void fail(PolicyChain policyChain, String remoteAddress) {
        policyChain.failWith(PolicyResult.failure(
                HttpStatusCode.FORBIDDEN_403,
                "Your IP (" + remoteAddress + ") or some proxies whereby your request pass through are not allowed to reach this resource."
        ));
    }

    public List<String> extractIps(Request request) {
        List<String> ips;

        if (configuration.isMatchAllFromXForwardedFor()
                && request.headers() != null
                && request.headers().get(HttpHeaderNames.X_FORWARDED_FOR) != null
                && !request.headers().get(HttpHeaderNames.X_FORWARDED_FOR).isEmpty()) {
            ips = Arrays.stream(request.headers().get(HttpHeaderNames.X_FORWARDED_FOR).split(","))
                    .map(String::trim).collect(toList());
        } else {
            ips = singletonList(request.remoteAddress());
        }
        return ips;
    }

    public boolean isFiltered(String ip, List<String> filteredList) {
        return !(null == ip || ip.isEmpty())
                && filteredList.stream().anyMatch(filterIp -> {
                    if (filterIp.equals(ip)) {
                        return true;
                    }
                    try {
                        SubnetUtils utils = new SubnetUtils(filterIp);
                        return utils.getInfo().isInRange(ip);
                    } catch (IllegalArgumentException iae) {
                        return false;
                    }
                });
    }

    private DnsClient getDnsClient(ExecutionContext context) {
        if (dnsClient == null) {
            dnsClient = context.getComponent(Vertx.class).createDnsClient();
        }

        return dnsClient;
    }
}
