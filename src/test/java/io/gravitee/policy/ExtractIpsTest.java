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
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.policy.ipfiltering.IPFilteringPolicy;
import io.gravitee.policy.ipfiltering.IPFilteringPolicyConfiguration;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
public class ExtractIpsTest {

    @Mock
    Request mockRequest;

    IPFilteringPolicyConfiguration filteringPolicyConfiguration;

    @BeforeEach
    public void beforeEach() {
        filteringPolicyConfiguration = new IPFilteringPolicyConfiguration();
    }

    @Test
    public void should_return_remote_address() {
        filteringPolicyConfiguration.setMatchAllFromXForwardedFor(false);
        when(mockRequest.remoteAddress()).thenReturn("127.0.0.1");
        IPFilteringPolicy policy = new IPFilteringPolicy(filteringPolicyConfiguration);
        List<String> ips = policy.extractIps(mockRequest);

        assertThat(ips).hasSize(1).containsOnly("127.0.0.1");
        verify(mockRequest, never()).headers();
    }

    @Test
    public void should_return_XForwardFor() {
        filteringPolicyConfiguration.setMatchAllFromXForwardedFor(true);
        HttpHeaders httpHeaders = HttpHeaders.create().set(HttpHeaderNames.X_FORWARDED_FOR, "localhost, 10.0.0.1, 192.168.0.5, unknown");
        when(mockRequest.headers()).thenReturn(httpHeaders);
        IPFilteringPolicy policy = new IPFilteringPolicy(filteringPolicyConfiguration);

        List<String> ips = policy.extractIps(mockRequest);

        assertThat(ips).hasSize(4).containsOnly("localhost", "10.0.0.1", "192.168.0.5", "unknown");
        verify(mockRequest, atLeastOnce()).headers();
        verify(mockRequest, never()).remoteAddress();
    }
}
