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
package io.gravitee.policy.ipfiltering;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.*;

import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.el.TemplateContext;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.node.api.configuration.Configuration;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.reactivex.Maybe;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.dns.DnsClient;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

@SuppressWarnings("removal")
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

    @Mock
    LazyDnsClient lazyDnsClient;

    @Mock
    Configuration globalConfiguration;

    private final TemplateEngine templateEngine = new TemplateEngine() {
        @Override
        @SuppressWarnings("unchecked")
        public <T> T getValue(String expression, Class<T> clazz) {
            if ("{#api.properties['allowed_ip']".equals(expression)) {
                return (T) "192.168.0.1";
            }
            if ("{#api.properties['forbidden_ip']}".equals(expression)) {
                return (T) "192.168.0.2";
            }
            if ("{#api.properties['list_of_allowed_ips']}".equals(expression)) {
                return (T) "192.168.0.1,192.168.0.2";
            }
            if ("{#api.properties['list_of_forbidden_ips']}".equals(expression)) {
                return (T) "192.168.0.3,192.168.0.4";
            }
            return (T) expression;
        }

        @Override
        public <T> Maybe<T> eval(String expression, Class<T> clazz) {
            return null;
        }

        @Override
        public TemplateContext getTemplateContext() {
            return null;
        }
    };

    @Before
    public void init() {
        when(executionContext.getTemplateEngine()).thenReturn(templateEngine);
        when(executionContext.request()).thenReturn(mockRequest);
        when(executionContext.response()).thenReturn(mockResponse);
    }

    @Test
    public void shouldResolveTemplates() {
        when(mockConfiguration.getWhitelistIps()).thenReturn(List.of("{#api.properties['allowed_ip']"));
        when(mockConfiguration.getBlacklistIps()).thenReturn(List.of("{#api.properties['forbidden_ip']}"));

        when(mockRequest.remoteAddress()).thenReturn("192.168.0.1");
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockPolicychain, never()).failWith(any(PolicyResult.class));
        verify(mockPolicychain, times(1)).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void shouldNotTestXFF() {
        when(mockConfiguration.isMatchAllFromXForwardedFor()).thenReturn(false);
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockConfiguration, times(1)).isMatchAllFromXForwardedFor();
        verify(mockRequest, never()).headers();
    }

    @Test
    public void shouldTestXFF() {
        when(mockConfiguration.isMatchAllFromXForwardedFor()).thenReturn(true);
        when(mockRequest.headers()).thenReturn(HttpHeaders.create().set(HttpHeaderNames.X_FORWARDED_FOR, "localhost"));
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
    public void shouldFailCausedIpNotInWhitelistPropertyList() {
        when(mockConfiguration.getWhitelistIps()).thenReturn(Arrays.asList("{api.properties['list_of_allowed_ips']", "192.168.0.5"));
        when(mockRequest.remoteAddress()).thenReturn("192.168.0.4");
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);

        policy.onRequest(executionContext, mockPolicychain);

        verify(mockPolicychain, times(1)).failWith(any(PolicyResult.class));
        verify(mockPolicychain, never()).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void shouldFailCausedIpInBlacklistPropertyList() {
        when(mockConfiguration.getBlacklistIps()).thenReturn(Arrays.asList("192.168.0.3,192.168.0.4", "192.168.0.5"));
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
            "Your IP (localhost, 10.0.0.1, 192.168.0.2, unknown) or some proxies whereby your request pass through are not allowed to reach this resource.",
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

    @Test
    public void shouldResolveHostnameInWhitelistAndAllowRequest() throws NoSuchFieldException, IllegalAccessException {
        Field dnsClientField = LazyDnsClient.class.getDeclaredField("dnsClient");
        dnsClientField.setAccessible(true);
        dnsClientField.set(null, null);
        when(mockConfiguration.isUseCustomIPAddress()).thenReturn(false);
        when(mockConfiguration.getWhitelistIps()).thenReturn(List.of("example.com"));
        when(mockConfiguration.getBlacklistIps()).thenReturn(List.of());
        when(mockRequest.remoteAddress()).thenReturn("93.184.216.34");
        when(mockConfiguration.getLookupIpVersion()).thenReturn(LookupIpVersion.ALL);

        Configuration mockGlobalConfig = mock(Configuration.class);
        when(mockGlobalConfig.getProperty("policy.ip-filtering.dns.host", String.class)).thenReturn("127.0.0.1");
        when(mockGlobalConfig.getProperty("policy.ip-filtering.dns.port", Integer.class)).thenReturn(53);
        when(executionContext.getComponent(Configuration.class)).thenReturn(mockGlobalConfig);

        Vertx mockVertx = mock(Vertx.class);
        DnsClient mockDnsClient = mock(DnsClient.class);
        when(executionContext.getComponent(Vertx.class)).thenReturn(mockVertx);
        when(mockVertx.createDnsClient(any())).thenReturn(mockDnsClient);
        when(mockDnsClient.resolveA("example.com")).thenReturn(Future.succeededFuture(List.of("93.184.216.34")));

        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);
        policy.onRequest(executionContext, mockPolicychain);

        verify(mockPolicychain, never()).failWith(any(PolicyResult.class));
        verify(mockPolicychain, times(1)).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void shouldNotAllowRequestWhenHostnameNotResolved() throws NoSuchFieldException, IllegalAccessException {
        Field dnsClientField = LazyDnsClient.class.getDeclaredField("dnsClient");
        dnsClientField.setAccessible(true);
        dnsClientField.set(null, null);
        when(mockConfiguration.isUseCustomIPAddress()).thenReturn(false);
        when(mockConfiguration.getWhitelistIps()).thenReturn(List.of("example.com"));
        when(mockConfiguration.getBlacklistIps()).thenReturn(List.of());
        when(mockRequest.remoteAddress()).thenReturn("93.184.216.34");
        when(mockConfiguration.getLookupIpVersion()).thenReturn(LookupIpVersion.ALL);
        Configuration mockGlobalConfig = mock(Configuration.class);
        when(mockGlobalConfig.getProperty("policy.ip-filtering.dns.host", String.class)).thenReturn("127.0.0.1");
        when(mockGlobalConfig.getProperty("policy.ip-filtering.dns.port", Integer.class)).thenReturn(53);
        when(executionContext.getComponent(Configuration.class)).thenReturn(mockGlobalConfig);
        Vertx mockVertx = mock(Vertx.class);
        DnsClient mockDnsClient = mock(DnsClient.class);
        when(executionContext.getComponent(Vertx.class)).thenReturn(mockVertx);
        when(mockVertx.createDnsClient(any())).thenReturn(mockDnsClient);
        when(mockDnsClient.resolveA("example.com"))
            .thenAnswer(invocation -> {
                Promise<Void> promise = Promise.promise();
                promise.fail(new Throwable("DNS resolution failed"));
                return promise.future();
            });
        when(mockDnsClient.resolveAAAA("example.com"))
            .thenAnswer(invocation -> {
                Promise<Void> promise = Promise.promise();
                promise.fail(new Throwable("DNS resolution failed"));
                return promise.future();
            });
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);

        policy.onRequest(executionContext, mockPolicychain);
        verify(mockPolicychain, times(1)).failWith(any(PolicyResult.class));
        verify(mockPolicychain, never()).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void shouldFailWhenHostResolvesToBlacklistedIp() throws NoSuchFieldException, IllegalAccessException {
        Field dnsClientField = LazyDnsClient.class.getDeclaredField("dnsClient");
        dnsClientField.setAccessible(true);
        dnsClientField.set(null, null);
        when(mockConfiguration.isUseCustomIPAddress()).thenReturn(false);
        when(mockConfiguration.getBlacklistIps()).thenReturn(List.of("example.com"));
        when(mockRequest.remoteAddress()).thenReturn("203.0.113.10");
        when(mockConfiguration.getLookupIpVersion()).thenReturn(LookupIpVersion.ALL);
        Configuration mockGlobalConfig = mock(Configuration.class);
        when(mockGlobalConfig.getProperty("policy.ip-filtering.dns.host", String.class)).thenReturn("127.0.0.1");
        when(mockGlobalConfig.getProperty("policy.ip-filtering.dns.port", Integer.class)).thenReturn(53);
        when(executionContext.getComponent(Configuration.class)).thenReturn(mockGlobalConfig);

        Vertx mockVertx = mock(Vertx.class);
        DnsClient mockDnsClient = mock(DnsClient.class);
        when(executionContext.getComponent(Vertx.class)).thenReturn(mockVertx);
        when(mockVertx.createDnsClient(any())).thenReturn(mockDnsClient);
        when(mockDnsClient.resolveA("example.com")).thenReturn(Future.succeededFuture(List.of("203.0.113.10")));
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);
        policy.onRequest(executionContext, mockPolicychain);
        verify(mockPolicychain, times(1)).failWith(any(PolicyResult.class));
        verify(mockPolicychain, never()).doNext(any(Request.class), any(Response.class));
    }

    @Test
    public void isIpInFilterIpRange_ipV4_in_filterIpRange() {
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);
        String ip = "192.168.0.1";
        String filterIp = "192.168.0.0/24";
        boolean res = policy.isIpInFilterIpRange(ip, filterIp);
        assertTrue(res);
    }

    @Test
    public void isIpInFilterIpRange_networkIpV4_in_filterIpRange_isNotInclusiveHostCount() {
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);
        String ip = "192.168.0.0";
        String filterIp = "192.168.0.0/24";
        boolean res = policy.isIpInFilterIpRange(ip, filterIp);
        assertFalse(res);
    }

    @Test
    public void isIpInFilterIpRange_networkIpV4_in_filterIpRange_isInclusiveHostCount() {
        IPFilteringPolicyConfiguration configuration = new IPFilteringPolicyConfiguration();
        configuration.setIsInclusiveHostCount(true);
        IPFilteringPolicy policy = new IPFilteringPolicy(configuration);
        String ip = "192.168.0.0";
        String filterIp = "192.168.0.0/24";
        boolean res = policy.isIpInFilterIpRange(ip, filterIp);
        assertTrue(res);
    }

    @Test
    public void isIpInFilterIpRange_broadcastIpV4_in_filterIpRange_isNotInclusiveHostCount() {
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);
        String ip = "192.168.0.255";
        String filterIp = "192.168.0.0/24";
        boolean res = policy.isIpInFilterIpRange(ip, filterIp);
        assertFalse(res);
    }

    @Test
    public void isIpInFilterIpRange_broadcastIpV4_in_filterIpRange_isInclusiveHostCount() {
        IPFilteringPolicyConfiguration configuration = new IPFilteringPolicyConfiguration();
        configuration.setIsInclusiveHostCount(true);
        IPFilteringPolicy policy = new IPFilteringPolicy(configuration);
        String ip = "192.168.0.255";
        String filterIp = "192.168.0.0/24";
        boolean res = policy.isIpInFilterIpRange(ip, filterIp);
        assertTrue(res);
    }

    @Test
    public void isIpInFilterIpRange_ipV4_not_in_filterIpRange() {
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);
        String ip = "192.168.0.1";
        String filterIp = "192.169.0.0/24";
        boolean res = policy.isIpInFilterIpRange(ip, filterIp);
        assertFalse(res);
    }

    @Test
    public void isIpInFilterIpRange_ipV6_in_filterIpRange() {
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);
        String ip = "2001:db8::1";
        String filterIp = "2001:db8::/64";
        boolean res = policy.isIpInFilterIpRange(ip, filterIp);
        assertTrue(res);
    }

    @Test
    public void isIpInFilterIpRange_ipV6_not_in_filterIpRange() {
        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);
        String ip = "2001:db8::1";
        String filterIp = "2001:db9::/64";
        boolean res = policy.isIpInFilterIpRange(ip, filterIp);
        assertFalse(res);
    }

    @Test
    public void shouldAllowRequestWhenIpInWhitelistOrHostnameResolvesToWhitelist() throws InterruptedException {
        when(mockConfiguration.isUseCustomIPAddress()).thenReturn(false);
        when(mockConfiguration.getWhitelistIps()).thenReturn(List.of("93.184.216.34", "example.com"));
        when(mockConfiguration.getBlacklistIps()).thenReturn(List.of());
        when(mockRequest.remoteAddress()).thenReturn("93.184.216.34");
        when(mockConfiguration.getLookupIpVersion()).thenReturn(LookupIpVersion.ALL);

        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);
        CountDownLatch latch = new CountDownLatch(1);
        doAnswer(invocation -> {
                latch.countDown();
                return null;
            })
            .when(mockPolicychain)
            .doNext(any(), any());

        try (MockedStatic<LazyDnsClient> lazyDnsMock = mockStatic(LazyDnsClient.class)) {
            lazyDnsMock
                .when(() -> LazyDnsClient.lookup(any(), any(), eq("example.com"), any()))
                .thenAnswer(invocation -> {
                    var handler = invocation.getArgument(3, io.vertx.core.Handler.class);
                    handler.handle(Future.succeededFuture(List.of("93.184.216.34")));
                    return null;
                });
            policy.onRequest(executionContext, mockPolicychain);
        }
        assertTrue("PolicyChain did not complete in time", latch.await(1, TimeUnit.SECONDS));

        verify(mockPolicychain, never()).failWith(any());
        verify(mockPolicychain, times(1)).doNext(any(), any());
    }

    @Test
    public void shouldFailRequestWhenIpOrHostnameMatchesBlacklist() {
        when(mockConfiguration.isUseCustomIPAddress()).thenReturn(false);
        when(mockConfiguration.getWhitelistIps()).thenReturn(List.of());
        when(mockConfiguration.getBlacklistIps()).thenReturn(List.of("192.168.0.5", "badhost.com"));
        when(mockRequest.remoteAddress()).thenReturn("93.184.216.34"); // IP that will match the hostname
        when(mockConfiguration.getLookupIpVersion()).thenReturn(LookupIpVersion.ALL);

        IPFilteringPolicy policy = new IPFilteringPolicy(mockConfiguration);

        try (MockedStatic<LazyDnsClient> lazyDnsMock = mockStatic(LazyDnsClient.class)) {
            lazyDnsMock
                .when(() -> LazyDnsClient.lookup(any(), any(), eq("badhost.com"), any()))
                .thenAnswer(invocation -> {
                    var handler = invocation.getArgument(3, io.vertx.core.Handler.class);
                    // Simulate resolved IP matches the request IP → block
                    handler.handle(Future.succeededFuture(List.of("93.184.216.34")));
                    return null;
                });

            policy.onRequest(executionContext, mockPolicychain);
        }

        verify(mockPolicychain, times(1)).failWith(any());
        verify(mockPolicychain, never()).doNext(any(), any());
    }
}
