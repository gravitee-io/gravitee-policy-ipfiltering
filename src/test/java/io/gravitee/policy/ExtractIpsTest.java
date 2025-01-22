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
import static org.mockito.Mockito.*;
import static org.mockito.MockitoAnnotations.initMocks;

import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.policy.ipfiltering.IPFilteringPolicy;
import io.gravitee.policy.ipfiltering.IPFilteringPolicyConfiguration;
import java.util.Arrays;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class ExtractIpsTest {

    @Mock
    Request mockRequest;

    @Mock
    ExecutionContext executionContext;

    @Mock
    IPFilteringPolicyConfiguration mockConfiguration;

    @Before
    public void init() {
        initMocks(this);
    }

    @Test
    public void shouldReturnRemoteAddress() {
        when(mockConfiguration.isMatchAllFromXForwardedFor()).thenReturn(false);
        when(executionContext.request()).thenReturn(mockRequest);
        when(mockRequest.remoteAddress()).thenReturn("127.0.0.1");
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);

        List<String> ips = policy.extractIps(executionContext);

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
        HttpHeaders httpHeaders = HttpHeaders.create().set(HttpHeaderNames.X_FORWARDED_FOR, "localhost, 10.0.0.1, 192.168.0.5, unknown");
        when(executionContext.request()).thenReturn(mockRequest);
        when(mockRequest.headers()).thenReturn(httpHeaders);
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);

        List<String> ips = policy.extractIps(executionContext);

        assertNotNull(ips);
        assertFalse(ips.isEmpty());
        assertEquals(4, ips.size());
        assertEquals("localhost", ips.get(0));
        assertFalse(ips.contains("127.0.0.1"));
        verify(mockConfiguration, times(1)).isMatchAllFromXForwardedFor();
        verify(mockRequest, atLeastOnce()).headers();
        verify(mockRequest, never()).remoteAddress();
    }

    @Test
    public void shouldReturnCustomIPAddress() {
        when(mockConfiguration.isUseCustomIPAddress()).thenReturn(true);
        TemplateEngine mockTemplateEngine = mock(TemplateEngine.class);
        when(executionContext.getTemplateEngine()).thenReturn(mockTemplateEngine);
        when(mockTemplateEngine.getValue(any(), any())).thenReturn("192.168.1.1, 192.168.1.2");
        when(executionContext.request()).thenReturn(mockRequest);
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);

        List<String> ips = policy.extractIps(executionContext);

        assertNotNull(ips);
        assertFalse(ips.isEmpty());
        assertEquals(2, ips.size());
        assertEquals("192.168.1.1", ips.get(0));
        assertEquals("192.168.1.2", ips.get(1));
        verify(mockConfiguration, times(1)).isUseCustomIPAddress();
        verify(executionContext, times(1)).getTemplateEngine();
        verify(mockTemplateEngine, times(1)).getValue(any(), any());
        verify(mockRequest, never()).headers();
        verify(mockRequest, never()).remoteAddress();
    }
}
