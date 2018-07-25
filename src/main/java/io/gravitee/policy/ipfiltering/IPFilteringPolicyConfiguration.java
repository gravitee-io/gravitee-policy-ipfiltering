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

import com.fasterxml.jackson.annotation.JsonProperty;
import io.gravitee.policy.api.PolicyConfiguration;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@SuppressWarnings("unused")
public class IPFilteringPolicyConfiguration implements PolicyConfiguration {

    /**
     * true if X-Forwarded-For header param must be filtered, false otherwise
     */
    private boolean matchAllFromXForwardedFor = false;

    /**
     * The list of IP that are allowed to be call the api.
     */
    @JsonProperty("whitelistIps")
    private List<IpOrCIDRBlock> whitelistIpList;

    /**
     * The list of IP that are not allowed to be call the api.
     */
    @JsonProperty("blacklistIps")
    private List<IpOrCIDRBlock> blacklistIpList;

    public boolean isMatchAllFromXForwardedFor() {
        return matchAllFromXForwardedFor;
    }

    public void setMatchAllFromXForwardedFor(boolean matchAllFromXForwardedFor) {
        this.matchAllFromXForwardedFor = matchAllFromXForwardedFor;
    }

    public List<IpOrCIDRBlock> getWhitelistIpList() {
        return whitelistIpList;
    }

    public void setWhitelistIpList(List<IpOrCIDRBlock> whitelistIpList) {
        this.whitelistIpList = whitelistIpList;
    }

    public List<IpOrCIDRBlock> getBlacklistIpList() {
        return blacklistIpList;
    }

    public void setBlacklistIpList(List<IpOrCIDRBlock> blacklistIpList) {
        this.blacklistIpList = blacklistIpList;
    }

    /*
    public List<String> getWhitelistIps(){
        if (whitelistIpList != null) {
            return whitelistIpList.stream()
                    .map(IpOrCIDRBlock::getIpOrCIDR)
                    .collect(Collectors.toList());
        }

        return Collections.emptyList();
    }

    public List<String> getBlacklistIps(){
        if( blacklistIpList != null) {
            return blacklistIpList.stream()
                    .map(IpOrCIDRBlock::getIpOrCIDR)
                    .collect(Collectors.toList());
        }
        return Collections.emptyList();
    }
    */
}
