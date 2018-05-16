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

import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.ChainScope;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.Category;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.api.annotations.Policy;
import io.gravitee.policy.api.annotations.Scope;
import org.apache.commons.net.util.SubnetUtils;

import java.util.*;
import java.util.stream.Collectors;

@SuppressWarnings("unused")
@Policy(
        category = @Category(io.gravitee.policy.api.Category.SECURITY),
        scope = @Scope({ChainScope.API, ChainScope.PLAN})
)
public class IPFilteringPolicy {

    /**
     * The associated configuration to this IPFiltering Policy
     */
    private IPFilteringPolicyConfiguration configuration;

    /**
     * Create a new IPFiltering Policy instance based on its associated configuration
     *
     * @param configuration the associated configuration to the new IPFiltering Policy instance
     */
    public IPFilteringPolicy(IPFilteringPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, PolicyChain policyChain) {

        List<String> ips = extractIps(request);

        final boolean isBlacklisted =
                !(configuration.getBlacklistIps() == null || configuration.getBlacklistIps().isEmpty())
                && ips.stream().anyMatch(ip -> isFiltered(ip, configuration.getBlacklistIps()));
        if(isBlacklisted) {
            fail(policyChain, request.remoteAddress());
            return;
        } else {
            final boolean isWhitelisted =
                    (configuration.getWhitelistIps() == null || configuration.getWhitelistIps().isEmpty())
                    || ips.stream().anyMatch(ip -> isFiltered(ip, configuration.getWhitelistIps()));
            if(!isWhitelisted) {
                fail(policyChain, request.remoteAddress());
                return;
            }
        }

        policyChain.doNext(request, response);
    }

    public void fail(PolicyChain policyChain, String remoteAddress) {
        policyChain.failWith(PolicyResult.failure(
                HttpStatusCode.FORBIDDEN_403,
                "Your IP (" + remoteAddress + ") or some proxies whereby your request pass through are not allowed to reach this resource."
        ));
    }

    public List<String> extractIps(Request request) {
        List<String> ips;

        if (configuration.isMatchAllFromXForwardedFor()
                && request.headers() != null
                && request.headers().get(HttpHeaders.X_FORWARDED_FOR) != null
                && !request.headers().get(HttpHeaders.X_FORWARDED_FOR).isEmpty()) {
            ips = Arrays.asList(request.headers().get(HttpHeaders.X_FORWARDED_FOR).get(0).split(","))
                    .stream().map(String::trim).collect(Collectors.toList());
        } else {
            ips = Collections.singletonList(request.remoteAddress());
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
}
