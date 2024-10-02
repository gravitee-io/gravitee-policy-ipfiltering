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

import static org.mockito.Mockito.*;
import static org.mockito.MockitoAnnotations.initMocks;

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
import java.util.List;
import org.junit.Before;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
public class IPFilteringPolicyTest {

    @Mock
    ExecutionContext executionContext;

    @Mock
    Request mockRequest;

    @Mock
    Response mockResponse;

    @Mock
    PolicyChain mockPolicychain;

    IPFilteringPolicyConfiguration filteringPolicyConfiguration;

    @BeforeEach
    public void beforeEach() {
        filteringPolicyConfiguration = new IPFilteringPolicyConfiguration();
        lenient().when(executionContext.request()).thenReturn(mockRequest);
        lenient().when(executionContext.response()).thenReturn(mockResponse);
    }

    @Test
    public void should_not_test_XFF_header() {
        filteringPolicyConfiguration.setMatchAllFromXForwardedFor(false);
        filteringPolicyConfiguration.setWhitelistIps(List.of("127.0.0.1"));
        when(mockRequest.remoteAddress()).thenReturn("127.0.0.1");
        IPFilteringPolicy policy = new IPFilteringPolicy(filteringPolicyConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockRequest, never()).headers();
        verify(mockPolicychain, never()).failWith(any(PolicyResult.class));
        verify(mockPolicychain).doNext(any(), any());
    }

    @Test
    public void should_test_XFF() {
        filteringPolicyConfiguration.setMatchAllFromXForwardedFor(true);
        filteringPolicyConfiguration.setWhitelistIps(List.of("10.0.0.1"));
        HttpHeaders httpHeaders = HttpHeaders.create().set(HttpHeaderNames.X_FORWARDED_FOR, "localhost, 10.0.0.1, 192.168.0.5, unknown");
        when(mockRequest.headers()).thenReturn(httpHeaders);
        IPFilteringPolicy policy = new IPFilteringPolicy(filteringPolicyConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockRequest, atLeastOnce()).headers();
        verify(mockPolicychain, never()).failWith(any(PolicyResult.class));
        verify(mockPolicychain).doNext(any(), any());
    }

    @Test
    public void should_fail_caused_ip_in_blacklist() {
        filteringPolicyConfiguration.setBlacklistIps(List.of("192.168.0.1", "192.168.0.2", "192.168.0.3"));
        when(mockRequest.remoteAddress()).thenReturn("192.168.0.1");
        IPFilteringPolicy policy = new IPFilteringPolicy(filteringPolicyConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockPolicychain, times(1)).failWith(any(PolicyResult.class));
        verify(mockPolicychain, never()).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void should_fail_caused_ip_not_in_whitelist() {
        filteringPolicyConfiguration.setWhitelistIps(List.of("192.168.0.1", "192.168.0.2", "192.168.0.3"));
        when(mockRequest.remoteAddress()).thenReturn("192.168.0.4");
        IPFilteringPolicy policy = new IPFilteringPolicy(filteringPolicyConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockPolicychain, times(1)).failWith(any(PolicyResult.class));
        verify(mockPolicychain, never()).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void should_fail_caused_ip_in_blacklist_and_whitelist() {
        filteringPolicyConfiguration.setBlacklistIps(List.of("192.168.0.1", "192.168.0.2", "192.168.0.3"));
        filteringPolicyConfiguration.setWhitelistIps(List.of("192.168.0.1"));
        when(mockRequest.remoteAddress()).thenReturn("192.168.0.1");
        IPFilteringPolicy policy = new IPFilteringPolicy(filteringPolicyConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockPolicychain, times(1)).failWith(any(PolicyResult.class));
        verify(mockPolicychain, never()).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void should_fail_caused_ip_in_blacklist_and_not_in_whitelist() {
        filteringPolicyConfiguration.setBlacklistIps(List.of("192.168.0.1", "192.168.0.2", "192.168.0.3"));
        filteringPolicyConfiguration.setWhitelistIps(List.of("192.168.0.4", "192.168.0.5", "192.168.0.6"));

        when(mockRequest.remoteAddress()).thenReturn("192.168.0.1");
        IPFilteringPolicy policy = new IPFilteringPolicy(filteringPolicyConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockPolicychain, times(1)).failWith(any(PolicyResult.class));
        verify(mockPolicychain, never()).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void should_Fail_Caused_Ip_Not_In_Blacklist_And_Not_In_Whitelist() {
        filteringPolicyConfiguration.setBlacklistIps(List.of("192.168.0.1", "192.168.0.2", "192.168.0.3"));
        filteringPolicyConfiguration.setWhitelistIps(List.of("192.168.0.4", "192.168.0.5", "192.168.0.6"));
        when(mockRequest.remoteAddress()).thenReturn("192.168.0.7");
        IPFilteringPolicy policy = new IPFilteringPolicy(filteringPolicyConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockPolicychain, times(1)).failWith(any(PolicyResult.class));
        verify(mockPolicychain, never()).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void should_succeed_caused_ip_not_in_blacklist_and_nothing_in_whitelist() {
        filteringPolicyConfiguration.setBlacklistIps(List.of("192.168.0.1", "192.168.0.2", "192.168.0.3"));
        when(mockRequest.remoteAddress()).thenReturn("192.168.0.4");
        IPFilteringPolicy policy = new IPFilteringPolicy(filteringPolicyConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockPolicychain, never()).failWith(any(PolicyResult.class));
        verify(mockPolicychain, times(1)).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void should_succeed_caused_ip_not_in_blacklist_and_in_whitelist() {
        filteringPolicyConfiguration.setBlacklistIps(List.of("192.168.0.1", "192.168.0.2", "192.168.0.3"));
        filteringPolicyConfiguration.setWhitelistIps(List.of("192.168.0.4", "192.168.0.5", "192.168.0.6"));
        when(mockRequest.remoteAddress()).thenReturn("192.168.0.4");
        IPFilteringPolicy policy = new IPFilteringPolicy(filteringPolicyConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockPolicychain, never()).failWith(any(PolicyResult.class));
        verify(mockPolicychain, times(1)).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void should_succeed_caused_ips_not_in_blacklist_and_in_whitelist() {
        filteringPolicyConfiguration.setBlacklistIps(List.of("192.168.0.1", "192.168.0.2", "192.168.0.3"));
        filteringPolicyConfiguration.setWhitelistIps(List.of("192.168.0.4", "192.168.0.5", "192.168.0.6"));
        filteringPolicyConfiguration.setMatchAllFromXForwardedFor(true);
        HttpHeaders httpHeaders = HttpHeaders.create().set(HttpHeaderNames.X_FORWARDED_FOR, "localhost, 10.0.0.1, 192.168.0.5, unknown");
        when(mockRequest.headers()).thenReturn(httpHeaders);
        IPFilteringPolicy policy = new IPFilteringPolicy(filteringPolicyConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockPolicychain, never()).failWith(any(PolicyResult.class));
        verify(mockPolicychain, times(1)).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void should_failed_caused_ips_i_nblacklist() {
        filteringPolicyConfiguration.setBlacklistIps(List.of("192.168.0.1", "192.168.0.2", "192.168.0.3"));
        filteringPolicyConfiguration.setMatchAllFromXForwardedFor(true);
        HttpHeaders httpHeaders = HttpHeaders.create().set(HttpHeaderNames.X_FORWARDED_FOR, "localhost, 10.0.0.1, 192.168.0.2, unknown");
        when(mockRequest.headers()).thenReturn(httpHeaders);
        IPFilteringPolicy policy = new IPFilteringPolicy(filteringPolicyConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockPolicychain, times(1)).failWith(any(PolicyResult.class));
        verify(mockPolicychain, never()).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void should_succeed_with_null_value() {
        List<String> ips = new ArrayList<>();
        ips.add(null);
        filteringPolicyConfiguration.setBlacklistIps(ips);
        filteringPolicyConfiguration.setMatchAllFromXForwardedFor(true);
        HttpHeaders httpHeaders = HttpHeaders.create().set(HttpHeaderNames.X_FORWARDED_FOR, "localhost, 10.0.0.1, 192.168.0.2, unknown");
        when(mockRequest.headers()).thenReturn(httpHeaders);
        IPFilteringPolicy policy = new IPFilteringPolicy(filteringPolicyConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockPolicychain, never()).failWith(any(PolicyResult.class));
        verify(mockPolicychain, times(1)).doNext(any(Request.class), any(Response.class));
    }
}
