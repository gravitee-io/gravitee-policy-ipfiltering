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
package io.gravitee.policy;

import static org.assertj.core.api.Assertions.assertThat;

import io.gravitee.policy.ipfiltering.IPFilteringPolicy;
import io.gravitee.policy.ipfiltering.IPFilteringPolicyConfiguration;
import java.util.Arrays;
import java.util.Collections;
import org.junit.jupiter.api.Test;

public class IsFilteredTest {

    @Test
    public void should_not_filtered_if_empty_list() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("1.1.1.1", Collections.emptyList());

        assertThat(filtered).isFalse();
    }

    @Test
    public void should_not_filtered_if_empty_ip() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("", Collections.singletonList("1.1.1.1"));

        assertThat(filtered).isFalse();
    }

    @Test
    public void should_not_filtered_if_null_ip() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered(null, Collections.singletonList("1.1.1.1"));

        assertThat(filtered).isFalse();
    }

    @Test
    public void should_filtered_if_ips_are_equals_with_one_element_in_list() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("1.1.1.1", Collections.singletonList("1.1.1.1"));

        assertThat(filtered).isTrue();
    }

    @Test
    public void should_filtered_if_ips_are_equals_with_multiple_element_in_list() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("1.1.1.1", Arrays.asList("1.1.0.1", "1.1.1.1", "1.1.2.1"));

        assertThat(filtered).isTrue();
    }

    @Test
    public void should_filtered_if_ip_is_not_an_ip() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("Gravitee.IO", Arrays.asList("1.1.0.1", "1.1.1.1", "1.1.2.1"));

        assertThat(filtered).isFalse();
    }

    @Test
    public void should_not_filtered_if_ips_are_not_ips() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("1.1.1.1", Arrays.asList("Gravitee.IO", "is", "awesome"));

        assertThat(filtered).isFalse();
    }

    // from 192.168.0.0 to 192.168.0.255 => 192.168.0.0/24
    @Test
    public void should_filtered_cidr_for_mask_24() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        for (int i = 1; i < 255; i++) {
            boolean filtered = policy.isFiltered("192.168.0." + i, Collections.singletonList("192.168.0.0/24"));

            assertThat(filtered).as("should filter 192.168.0.%s", i).isTrue();
        }
    }

    @Test
    public void should_filtered_single_cidr_for_mask_32() {
        IPFilteringPolicyConfiguration configuration = new IPFilteringPolicyConfiguration();
        configuration.setInclusiveHostCount(true);
        IPFilteringPolicy policy = new IPFilteringPolicy(configuration);

        boolean filtered = policy.isFiltered("20.126.185.99", Collections.singletonList("20.126.185.99/32"));
        assertThat(filtered).isTrue();
    }

    @Test
    public void should_filtered_cidr_with_is_inclusive_host_count() {
        IPFilteringPolicyConfiguration configuration = new IPFilteringPolicyConfiguration();
        configuration.setInclusiveHostCount(true);
        IPFilteringPolicy policy = new IPFilteringPolicy(configuration);

        boolean filtered = policy.isFiltered("192.168.1.0", Collections.singletonList("192.168.1.0/31"));

        assertThat(filtered).isTrue();
    }

    /**
     * TEST CIDR
     */
    // from 192.168.0.0 to 192.168.0.255 => 192.168.0.0/24
    @Test
    public void should_not_filtered_cidr_192_168_0_0_for_mask_24() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("192.168.0.0", Collections.singletonList("192.168.0.0/24"));

        assertThat(filtered).isFalse();
    }

    // from 192.168.0.0 to 192.168.0.255 => 192.168.0.0/24
    @Test
    public void should_not_filtered_cidr_192_168_0_255_for_mask_24() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("192.168.0.255", Collections.singletonList("192.168.0.0/24"));

        assertThat(filtered).isFalse();
    }

    // from 192.168.0.0 to 192.168.3.255 => 192.168.0.0/22
    @Test
    public void should_not_filtered_cidr_192_168_0_0_for_mask_22() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("192.168.0.0", Collections.singletonList("192.168.0.0/22"));

        assertThat(filtered).isFalse();
    }

    // from 192.168.0.0 to 192.168.3.255 => 192.168.0.0/22
    @Test
    public void should_filtered_cidr_192_168_0_255_for_mask_22() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("192.168.0.255", Collections.singletonList("192.168.0.0/22"));

        assertThat(filtered).isTrue();
    }

    // from 192.168.0.0 to 192.168.3.255 => 192.168.0.0/22
    @Test
    public void should_filtered_cidr_192_168_3_254_for_mask_22() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("192.168.3.254", Collections.singletonList("192.168.0.0/22"));

        assertThat(filtered).isTrue();
    }

    // from 192.168.0.0 to 192.168.3.255 => 192.168.0.0/22
    @Test
    public void should_not_filtered_cidr_192_168_3_255_for_mask_22() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("192.168.3.255", Collections.singletonList("192.168.0.0/22"));

        assertThat(filtered).isFalse();
    }

    @Test
    public void should_filtered_when_ip_is_in_list() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("192.168.0.2", Arrays.asList("192.168.0.1", "192.168.0.2", "192.168.0.3"));

        assertThat(filtered).isTrue();
    }

    @Test
    public void should_not_filtered_when_ip_is_not_in_list() {
        IPFilteringPolicy policy = new IPFilteringPolicy(new IPFilteringPolicyConfiguration());

        boolean filtered = policy.isFiltered("192.168.0.4", Arrays.asList("192.168.0.1", "192.168.0.2", "192.168.0.3"));

        assertThat(filtered).isFalse();
    }
}
