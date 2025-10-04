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
import io.netty.handler.ipfilter.IpFilterRuleType;
import io.netty.handler.ipfilter.IpSubnetFilterRule;
import io.vertx.core.CompositeFuture;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
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

            boolean ipMatched = !filteredIps.isEmpty() && ips.stream().anyMatch(ip -> isFiltered(ip, filteredIps));
            if (!filteredHosts.isEmpty()) {
                blacklistFilteredHostsProcess(filteredHosts, futures, executionContext, ips);
            }
            if (!futures.isEmpty()) {
                CompositeFuture
                    .all(futures)
                    .onComplete(ar -> {
                        if (ipMatched || ar.failed()) {
                            LOGGER.warn("Request blocked: IP {} matched blacklist hosts {}", ips, filteredHosts);
                            fail(policyChain, String.join(", ", ips));
                        } else {
                            policyChain.doNext(executionContext.request(), executionContext.response());
                        }
                    });
                return;
            } else if (ipMatched) {
                fail(policyChain, String.join(", ", ips));
                return;
            }
        }

        if (!whiteList.isEmpty()) {
            final List<String> filteredIps = new ArrayList<>();
            final List<String> filteredHosts = new ArrayList<>();
            processFilteredLists(whiteList, filteredIps, filteredHosts);

            boolean ipMatched = !filteredIps.isEmpty() && ips.stream().anyMatch(ip -> isFiltered(ip, filteredIps));
            if (!filteredHosts.isEmpty()) {
                whitelistFilteredHostsProcess(filteredHosts, futures, executionContext, ips);
            }

            if (!futures.isEmpty()) {
                CompositeFuture
                    .all(futures)
                    .onComplete(ar -> {
                        if (ipMatched || ar.succeeded()) {
                            policyChain.doNext(executionContext.request(), executionContext.response());
                        } else {
                            LOGGER.warn("Request blocked: IPs {} did not match whitelist IPs or hosts {}", ips, filteredHosts);
                            fail(policyChain, String.join(", ", ips));
                        }
                    });
                return;
            } else if (ipMatched) {
                policyChain.doNext(executionContext.request(), executionContext.response());
                return;
            } else {
                fail(policyChain, String.join(", ", ips));
                return;
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

    /**
     * @param filteredHosts A list of hosts that should be blocked
     * @param futures
     * @param executionContext
     * @param ips The IP addresses corresponding to the calling device
     */
    private void blacklistFilteredHostsProcess(
        List<String> filteredHosts,
        List<Future> futures,
        ExecutionContext executionContext,
        List<String> ips
    ) {
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
                        promise.fail("Cannot resolve host: '" + host + "'");
                    }
                }
            );
        });
    }

    /**
     * @param filteredHosts A list of hosts that should be allowed
     * @param futures
     * @param executionContext
     * @param ips The IP addresses corresponding to the calling device
     */
    private void whitelistFilteredHostsProcess(
        List<String> filteredHosts,
        List<Future> futures,
        ExecutionContext executionContext,
        List<String> ips
    ) {
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
                        promise.fail("Cannot resolve host: '" + host + "'");
                    }
                }
            );
        });
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
        LOGGER.info("Filtering IP: {} against filter list: {}", ip, filteredList);
        return (
            !(null == ip || ip.isEmpty()) &&
            filteredList
                .stream()
                .anyMatch(filterIp -> {
                    if (filterIp.equals(ip)) {
                        return true;
                    }
                    return isIpInFilterIpRange(ip, filterIp);
                })
        );
    }

    boolean isIpInFilterIpRange(String ip, String filterIp) {
        try {
            if (isIPv4(ip)) {
                SubnetUtils utils = new SubnetUtils(filterIp);
                utils.setInclusiveHostCount(configuration.getIsInclusiveHostCount());
                return utils.getInfo().isInRange(ip);
            } else {
                IpSubnetFilterRule rule = new IpSubnetFilterRule(filterIp, IpFilterRuleType.ACCEPT);
                return rule.matches(new InetSocketAddress(ip, 0));
            }
        } catch (IllegalArgumentException | UnknownHostException iae) {
            return false;
        }
    }

    private static boolean isIPv4(String ip) throws UnknownHostException {
        return InetAddress.getByName(ip) instanceof java.net.Inet4Address;
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
