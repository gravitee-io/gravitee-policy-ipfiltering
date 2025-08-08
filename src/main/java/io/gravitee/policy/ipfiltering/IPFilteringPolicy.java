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

import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.toList;

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
import java.util.*;
import java.util.stream.Collectors;
import org.apache.commons.net.util.SubnetUtils;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Nicolas GERAUD (nicolas.geraud at graviteesource.com)
 * @author Azize ELAMRANI (azize.elamrani at graviteesource.com)
 * @author GraviteeSource Team
 */
public class IPFilteringPolicy {

    private static final Logger LOGGER = LoggerFactory.getLogger(IPFilteringPolicy.class);

    private final IPFilteringPolicyConfiguration configuration;

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
        final List<String> ips = extractIps(executionContext);
        final List<Future> futures = new ArrayList<>();

        var blackList = computeList(executionContext, configuration.getBlacklistIps());
        var whiteList = computeList(executionContext, configuration.getWhitelistIps());

        if (!blackList.isEmpty()) {
            final List<String> filteredIps = new ArrayList<>();
            final List<String> filteredHosts = new ArrayList<>();
            processFilteredLists(blackList, filteredIps, filteredHosts);
            Optional<String> matchingIp = ips.stream().filter(ip -> isFiltered(ip, filteredIps)).findFirst();
            if (!filteredIps.isEmpty() && matchingIp.isPresent()) {
                fail(policyChain, matchingIp.get());
                return;
            }

            if (!filteredHosts.isEmpty()) {
                filteredHosts.forEach(host -> {
                    final Promise<Void> promise = Promise.promise();
                    futures.add(promise.future());
                    LazyDnsClient.lookup(
                        executionContext,
                        configuration.getLookupIpVersion(),
                        host,
                        event -> {
                            if (event.succeeded()) {
                                List<String> resolvedIps = event.result();
                                boolean matchFound = ips.stream().anyMatch(resolvedIps::contains);
                                if (matchFound) {
                                    promise.fail("");
                                } else {
                                    promise.complete();
                                }
                            } else {
                                LOGGER.error("Cannot resolve host: '{}'", host, event.cause());
                                promise.complete();
                            }
                        }
                    );
                });
            }
        }

        if (!whiteList.isEmpty()) {
            final List<String> filteredIps = new ArrayList<>();
            final List<String> filteredHosts = new ArrayList<>();
            processFilteredLists(whiteList, filteredIps, filteredHosts);
            List<String> nonWhitelistedIps = ips.stream().filter(ip -> !isFiltered(ip, filteredIps)).collect(Collectors.toList());

            if (!filteredIps.isEmpty() && nonWhitelistedIps.size() == ips.size()) {
                fail(policyChain, String.join(", ", nonWhitelistedIps));
                return;
            }

            if (!filteredHosts.isEmpty()) {
                filteredHosts.forEach(host -> {
                    final Promise<Void> promise = Promise.promise();
                    futures.add(promise.future());
                    LazyDnsClient.lookup(
                        executionContext,
                        configuration.getLookupIpVersion(),
                        host,
                        event -> {
                            if (event.succeeded()) {
                                List<String> resolvedIps = event.result();
                                boolean matchFound = ips.stream().anyMatch(resolvedIps::contains);
                                if (!matchFound) {
                                    promise.fail("");
                                } else {
                                    promise.complete();
                                }
                            } else {
                                LOGGER.error("Cannot resolve host: '{}'", host, event.cause());
                                promise.complete();
                            }
                        }
                    );
                });
            }
        }

        if (futures.isEmpty()) {
            policyChain.doNext(executionContext.request(), executionContext.response());
        } else {
            CompositeFuture
                .all(futures)
                .onSuccess(__ -> policyChain.doNext(executionContext.request(), executionContext.response()))
                .onFailure(__ -> fail(policyChain, executionContext.request().remoteAddress()));
        }
    }

    private void processFilteredLists(final Set<String> filteredList, final List<String> filteredIps, final List<String> filteredHosts) {
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
        policyChain.failWith(
            PolicyResult.failure(
                HttpStatusCode.FORBIDDEN_403,
                "Your IP (" + remoteAddress + ") or some proxies whereby your request pass through are not allowed to reach this resource."
            )
        );
    }

    public List<String> extractIps(ExecutionContext context) {
        List<String> ips;
        Request request = context.request();

        //use Custom IP Address from an EL or static value
        if (configuration.isUseCustomIPAddress()) {
            String customIPAddress = context.getTemplateEngine().getValue(configuration.getCustomIPAddress(), String.class);
            ips = Arrays.stream(customIPAddress.split(",")).map(String::trim).collect(Collectors.toList());
        } else if (configuration.isMatchAllFromXForwardedFor()) {
            //use X-Forwarded-For header value directly (for compatibility)
            ips = Arrays.stream(request.headers().get(HttpHeaderNames.X_FORWARDED_FOR).split(",")).map(String::trim).collect(toList());
        } else {
            //default way to get IP Address
            ips = singletonList(request.remoteAddress());
        }
        return ips;
    }

    public boolean isFiltered(String ip, List<String> filteredList) {
        return (
            !(null == ip || ip.isEmpty()) &&
            filteredList
                .stream()
                .anyMatch(filterIp -> {
                    if (filterIp.equals(ip)) {
                        return true;
                    }
                    try {
                        SubnetUtils utils = new SubnetUtils(filterIp);
                        if (configuration.getIsInclusiveHostCount()) {
                            utils.setInclusiveHostCount(true);
                        }
                        return utils.getInfo().isInRange(ip);
                    } catch (IllegalArgumentException iae) {
                        return false;
                    }
                })
        );
    }

    @SuppressWarnings({ "removal" })
    private static Set<String> computeList(ExecutionContext ctx, List<String> givenList) {
        if (givenList == null) {
            return Set.of();
        }
        return givenList
            .stream()
            .map(given -> ctx.getTemplateEngine().getValue(given, String.class))
            .map(k -> k != null && !k.isEmpty() ? k.split(",") : new String[] {})
            .flatMap(Arrays::stream)
            .collect(Collectors.toSet());
    }
}
