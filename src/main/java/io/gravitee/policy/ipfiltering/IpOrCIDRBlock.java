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

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.gravitee.policy.ipfiltering.jackson.IpOrCIDRBlockDeserializer;

@JsonDeserialize(using = IpOrCIDRBlockDeserializer.class)
public final class IpOrCIDRBlock {
    private String ipOrCIDR;
    private String info;

    public IpOrCIDRBlock(String ipOrCIDR) {
        this.ipOrCIDR = ipOrCIDR;
    }

    public IpOrCIDRBlock(String ipOrCIDR, String info) {
        this.ipOrCIDR = ipOrCIDR;
        this.info = info;
    }

    public String getIpOrCIDR() {
        return ipOrCIDR;
    }

    public void setIpOrCIDR(String ipOrCIDR) {
        this.ipOrCIDR = ipOrCIDR;
    }

    public String getInfo() {
        return info;
    }

    public void setInfo(String info) {
        this.info = info;
    }
}