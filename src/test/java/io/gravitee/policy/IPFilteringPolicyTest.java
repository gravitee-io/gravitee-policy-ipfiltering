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

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;
import static org.mockito.MockitoAnnotations.initMocks;

import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.ipfiltering.IPFilteringPolicy;
import io.gravitee.policy.ipfiltering.IPFilteringPolicyConfiguration;
import java.util.ArrayList;
import java.util.Arrays;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class IPFilteringPolicyTest {

    @Mock
    ExecutionContext executionContext;

    @Mock
    Request mockRequest;

    @Mock
    Response mockResponse;

    @Mock
    PolicyChain mockPolicychain;

    @Mock
    IPFilteringPolicyConfiguration mockConfiguration;

    @Before
    public void init() {
        initMocks(this);
        when(executionContext.request()).thenReturn(mockRequest);
        when(executionContext.response()).thenReturn(mockResponse);
    }

    @Test
    public void shouldNotTestXFF() throws Exception {
        when(mockConfiguration.isMatchAllFromXForwardedFor()).thenReturn(false);
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockConfiguration, times(1)).isMatchAllFromXForwardedFor();
        verify(mockRequest, never()).headers();
    }

    @Test
    public void shouldTestXFF() throws Exception {
        when(mockConfiguration.isMatchAllFromXForwardedFor()).thenReturn(true);
        when(mockRequest.headers()).thenReturn(HttpHeaders.create());
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockConfiguration, times(1)).isMatchAllFromXForwardedFor();
        verify(mockRequest, atLeastOnce()).headers();
    }

    @Test
    public void shouldFailCausedIpInBlacklist() {
        when(mockConfiguration.getBlacklistIps()).thenReturn(Arrays.asList("192.168.0.1", "192.168.0.2", "192.168.0.3"));
        when(mockRequest.remoteAddress()).thenReturn("192.168.0.1");
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockPolicychain, times(1)).failWith(any(PolicyResult.class));
        verify(mockPolicychain, never()).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void shouldFailCausedIpNotInWhitelist() {
        when(mockConfiguration.getWhitelistIps()).thenReturn(Arrays.asList("192.168.0.1", "192.168.0.2", "192.168.0.3"));
        when(mockRequest.remoteAddress()).thenReturn("192.168.0.4");
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockPolicychain, times(1)).failWith(any(PolicyResult.class));
        verify(mockPolicychain, never()).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void shouldFailCausedIpInBlacklistAndWhitelist() {
        when(mockConfiguration.getBlacklistIps()).thenReturn(Arrays.asList("192.168.0.1", "192.168.0.2", "192.168.0.3"));
        when(mockRequest.remoteAddress()).thenReturn("192.168.0.1");
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockPolicychain, times(1)).failWith(any(PolicyResult.class));
        verify(mockPolicychain, never()).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void shouldFailCausedIpInBlacklistAndNotInWhitelist() {
        when(mockConfiguration.getBlacklistIps()).thenReturn(Arrays.asList("192.168.0.1", "192.168.0.2", "192.168.0.3"));
        when(mockConfiguration.getWhitelistIps()).thenReturn(Arrays.asList("192.168.0.4", "192.168.0.5", "192.168.0.6"));

        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockPolicychain, times(1)).failWith(any(PolicyResult.class));
        verify(mockPolicychain, never()).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void shouldFailCausedIpNotInBlacklistAndNotInWhitelist() {
        when(mockConfiguration.getBlacklistIps()).thenReturn(Arrays.asList("192.168.0.1", "192.168.0.2", "192.168.0.3"));
        when(mockConfiguration.getWhitelistIps()).thenReturn(Arrays.asList("192.168.0.4", "192.168.0.5", "192.168.0.6"));
        when(mockRequest.remoteAddress()).thenReturn("192.168.0.7");
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockPolicychain, times(1)).failWith(any(PolicyResult.class));
        verify(mockPolicychain, never()).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void shouldSucceedCausedIpNotInBlacklistAndNothingInWhitelist() {
        when(mockConfiguration.getBlacklistIps()).thenReturn(Arrays.asList("192.168.0.1", "192.168.0.2", "192.168.0.3"));
        when(mockRequest.remoteAddress()).thenReturn("192.168.0.4");
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockPolicychain, never()).failWith(any(PolicyResult.class));
        verify(mockPolicychain, times(1)).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void shouldSucceedCausedIpNotInBlacklistAndInWhitelist() {
        when(mockConfiguration.getBlacklistIps()).thenReturn(Arrays.asList("192.168.0.1", "192.168.0.2", "192.168.0.3"));
        when(mockConfiguration.getWhitelistIps()).thenReturn(Arrays.asList("192.168.0.4", "192.168.0.5", "192.168.0.6"));
        when(mockRequest.remoteAddress()).thenReturn("192.168.0.4");
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockPolicychain, never()).failWith(any(PolicyResult.class));
        verify(mockPolicychain, times(1)).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void shouldSucceedCausedIpsNotInBlacklistAndInWhitelist() {
        when(mockConfiguration.getBlacklistIps()).thenReturn(Arrays.asList("192.168.0.1", "192.168.0.2", "192.168.0.3"));
        when(mockConfiguration.getWhitelistIps()).thenReturn(Arrays.asList("192.168.0.4", "192.168.0.5", "192.168.0.6"));
        when(mockConfiguration.isMatchAllFromXForwardedFor()).thenReturn(true);
        HttpHeaders httpHeaders = HttpHeaders.create().set(HttpHeaderNames.X_FORWARDED_FOR, "localhost, 10.0.0.1, 192.168.0.5, unknown");
        when(mockRequest.headers()).thenReturn(httpHeaders);
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockPolicychain, never()).failWith(any(PolicyResult.class));
        verify(mockPolicychain, times(1)).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void shouldFailedCausedIpsInBlacklist() {
        when(mockConfiguration.getBlacklistIps()).thenReturn(Arrays.asList("192.168.0.1", "192.168.0.2", "192.168.0.3"));
        when(mockConfiguration.isMatchAllFromXForwardedFor()).thenReturn(true);
        HttpHeaders httpHeaders = HttpHeaders.create().set(HttpHeaderNames.X_FORWARDED_FOR, "localhost, 10.0.0.1, 192.168.0.2, unknown");
        when(mockRequest.headers()).thenReturn(httpHeaders);
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockPolicychain, times(1)).failWith(any(PolicyResult.class));
        verify(mockPolicychain, never()).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void shouldSucceedWithNullValue() {
        ArrayList<String> ips = new ArrayList<>();
        ips.add(null);

        when(mockConfiguration.getBlacklistIps()).thenReturn(ips);
        when(mockConfiguration.isMatchAllFromXForwardedFor()).thenReturn(true);
        HttpHeaders httpHeaders = HttpHeaders.create().set(HttpHeaderNames.X_FORWARDED_FOR, "localhost, 10.0.0.1, 192.168.0.2, unknown");
        when(mockRequest.headers()).thenReturn(httpHeaders);
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockPolicychain, never()).failWith(any(PolicyResult.class));
        verify(mockPolicychain, times(1)).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void shouldFailedCausedIpsInBlacklistAndReturnCorrectIP() {
        when(mockConfiguration.getBlacklistIps()).thenReturn(Arrays.asList("192.168.0.1", "192.168.0.2", "192.168.0.3"));
        when(mockConfiguration.isMatchAllFromXForwardedFor()).thenReturn(true);
        HttpHeaders httpHeaders = HttpHeaders.create().set(HttpHeaderNames.X_FORWARDED_FOR, "localhost, 10.0.0.1, 192.168.0.2, unknown");
        when(mockRequest.headers()).thenReturn(httpHeaders);
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        ArgumentCaptor<PolicyResult> policyResultCaptor = ArgumentCaptor.forClass(PolicyResult.class);
        verify(mockPolicychain, times(1)).failWith(policyResultCaptor.capture());
        PolicyResult policyResult = policyResultCaptor.getValue();
        assertEquals(
            "Your IP (192.168.0.2) or some proxies whereby your request pass through are not allowed to reach this resource.",
            policyResult.message()
        );
        assertEquals(HttpStatusCode.FORBIDDEN_403, policyResult.httpStatusCode());
        verify(mockPolicychain, never()).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void shouldFailedCausedIpsNotInWhitelistAndReturnCorrectIP() {
        when(mockConfiguration.getWhitelistIps()).thenReturn(Arrays.asList("192.168.0.4", "192.168.0.5", "192.168.0.6"));
        when(mockConfiguration.isMatchAllFromXForwardedFor()).thenReturn(true);
        HttpHeaders httpHeaders = HttpHeaders.create().set(HttpHeaderNames.X_FORWARDED_FOR, "localhost, 10.0.0.1, unknown");
        when(mockRequest.headers()).thenReturn(httpHeaders);
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        ArgumentCaptor<PolicyResult> policyResultCaptor = ArgumentCaptor.forClass(PolicyResult.class);
        verify(mockPolicychain, times(1)).failWith(policyResultCaptor.capture());
        PolicyResult policyResult = policyResultCaptor.getValue();
        assertEquals(
            "Your IP (localhost, 10.0.0.1, unknown) or some proxies whereby your request pass through are not allowed to reach this resource.",
            policyResult.message()
        );
        assertEquals(HttpStatusCode.FORBIDDEN_403, policyResult.httpStatusCode());
    }
}
