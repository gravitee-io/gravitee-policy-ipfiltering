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

import io.gravitee.common.http.HttpHeaders;
import io.gravitee.gateway.api.Request;
import io.gravitee.policy.ipfiltering.IPFilteringPolicy;
import io.gravitee.policy.ipfiltering.IPFilteringPolicyConfiguration;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.junit.Assert.*;

import java.util.List;

import static org.mockito.Mockito.*;
import static org.mockito.MockitoAnnotations.initMocks;

@RunWith(MockitoJUnitRunner.class)
public class ExtractIps {
    @Mock
    Request mockRequest;

    @Mock
    IPFilteringPolicyConfiguration mockConfiguration;

    @Before
    public void init() {
        initMocks(this);
    }

    @Test
    public void shouldReturnRemoteAddress() {
        when(mockConfiguration.isMatchAllFromXForwardedFor()).thenReturn(false);
        when(mockRequest.remoteAddress()).thenReturn("127.0.0.1");
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);

        List<String> ips = policy.extractIps(mockRequest);

        assertNotNull(ips);
        assertFalse(ips.isEmpty());
        assertEquals(1, ips.size());
        assertEquals("127.0.0.1", ips.get(0));
        verify(mockConfiguration, times(1)).isMatchAllFromXForwardedFor();
        verify(mockRequest, never()).headers();
    }

    @Test
    public void shouldReturnXFF() {
        when(mockConfiguration.isMatchAllFromXForwardedFor()).thenReturn(true);
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.set(HttpHeaders.X_FORWARDED_FOR, "localhost, 10.0.0.1, 192.168.0.5, unknown");
        when(mockRequest.headers()).thenReturn(httpHeaders);
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);

        List<String> ips = policy.extractIps(mockRequest);

        assertNotNull(ips);
        assertFalse(ips.isEmpty());
        assertEquals(4, ips.size());
        assertEquals("localhost", ips.get(0));
        assertFalse(ips.contains("127.0.0.1"));
        verify(mockConfiguration, times(1)).isMatchAllFromXForwardedFor();
        verify(mockRequest, atLeastOnce()).headers();
        verify(mockRequest, never()).remoteAddress();
    }
}
