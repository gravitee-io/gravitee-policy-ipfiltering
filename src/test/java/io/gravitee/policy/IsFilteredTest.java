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
package io.gravitee.policy;

import static org.junit.Assert.*;

import io.gravitee.policy.ipfiltering.IPFilteringPolicy;
import io.gravitee.policy.ipfiltering.IPFilteringPolicyConfiguration;
import java.util.Arrays;
import java.util.Collections;
import org.junit.Test;

public class IsFilteredTest {

    @Test
    public void shouldNotFilteredIfEmptyList() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("1.1.1.1", Collections.emptyList());

        assertFalse(filtered);
    }

    @Test
    public void shouldNotFilteredIfEmptyIp() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("", Collections.singletonList("1.1.1.1"));

        assertFalse(filtered);
    }

    @Test
    public void shouldNotFilteredIfNullIp() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered(null, Collections.singletonList("1.1.1.1"));

        assertFalse(filtered);
    }

    @Test
    public void shouldFilteredIfIpsAreEqualsWithOneElementInList() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("1.1.1.1", Collections.singletonList("1.1.1.1"));

        assertTrue(filtered);
    }

    @Test
    public void shouldFilteredIfIpsAreEqualsWithMultipleElementInList() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("1.1.1.1", Arrays.asList("1.1.0.1", "1.1.1.1", "1.1.2.1"));

        assertTrue(filtered);
    }

    @Test
    public void shouldFilteredIfIpIsNotAnIP() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("Gravitee.IO", Arrays.asList("1.1.0.1", "1.1.1.1", "1.1.2.1"));

        assertFalse(filtered);
    }

    @Test
    public void shouldNotFilteredIfIpsAreNotIps() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("1.1.1.1", Arrays.asList("Gravitee.IO", "is", "awesome"));

        assertFalse(filtered);
    }

    // from 192.168.0.0 to 192.168.0.255 => 192.168.0.0/24
    @Test
    public void shouldFilteredCIDR_ForMask_24() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        for (int i = 1; i < 255; i++) {
            boolean filtered = policy.isFiltered("192.168.0." + i, Collections.singletonList("192.168.0.0/24"));

            assertTrue("should filter 192.168.0." + i, filtered);
        }
    }

    /**
     * TEST CIDR
     */
    // from 192.168.0.0 to 192.168.0.255 => 192.168.0.0/24
    @Test
    public void shouldNotFilteredCIDR_192_168_0_0_ForMask_24() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("192.168.0.0", Collections.singletonList("192.168.0.0/24"));

        assertFalse(filtered);
    }

    // from 192.168.0.0 to 192.168.0.255 => 192.168.0.0/24
    @Test
    public void shouldNotFilteredCIDR_192_168_0_255_ForMask_24() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("192.168.0.255", Collections.singletonList("192.168.0.0/24"));

        assertFalse(filtered);
    }

    // from 192.168.0.0 to 192.168.3.255 => 192.168.0.0/22
    @Test
    public void shouldNotFilteredCIDR_192_168_0_0_ForMask_22() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("192.168.0.0", Collections.singletonList("192.168.0.0/22"));

        assertFalse(filtered);
    }

    // from 192.168.0.0 to 192.168.3.255 => 192.168.0.0/22
    @Test
    public void shouldFilteredCIDR_192_168_0_255_ForMask_22() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("192.168.0.255", Collections.singletonList("192.168.0.0/22"));

        assertTrue(filtered);
    }

    // from 192.168.0.0 to 192.168.3.255 => 192.168.0.0/22
    @Test
    public void shouldFilteredCIDR_192_168_3_254_ForMask_22() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("192.168.3.254", Collections.singletonList("192.168.0.0/22"));

        assertTrue(filtered);
    }

    // from 192.168.0.0 to 192.168.3.255 => 192.168.0.0/22
    @Test
    public void shouldNotFilteredCIDR_192_168_3_255_ForMask_22() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("192.168.3.255", Collections.singletonList("192.168.0.0/22"));

        assertFalse(filtered);
    }

    @Test
    public void shouldFilteredWhenIPIsInList() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("192.168.0.2", Arrays.asList("192.168.0.1", "192.168.0.2", "192.168.0.3"));

        assertTrue(filtered);
    }

    @Test
    public void shouldNotFilteredWhenIPIsNotInList() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("192.168.0.4", Arrays.asList("192.168.0.1", "192.168.0.2", "192.168.0.3"));

        assertFalse(filtered);
    }
}
