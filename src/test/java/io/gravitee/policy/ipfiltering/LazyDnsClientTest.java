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

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.node.api.configuration.Configuration;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.dns.DnsClient;
import io.vertx.core.dns.DnsClientOptions;
import java.util.Collections;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

public class LazyDnsClientTest {

    @Mock
    private ExecutionContext executionContext;

    @Mock
    private Configuration configuration;

    @Mock
    private Vertx vertx;

    @Mock
    private DnsClient dnsClient;

    @Before
    public void setup() {
        MockitoAnnotations.openMocks(this);

        when(executionContext.getComponent(Configuration.class)).thenReturn(configuration);
        when(executionContext.getComponent(Vertx.class)).thenReturn(vertx);
        when(vertx.createDnsClient(any(DnsClientOptions.class))).thenReturn(dnsClient);

        // Force reset the static field dnsClient
        try {
            java.lang.reflect.Field field = LazyDnsClient.class.getDeclaredField("dnsClient");
            field.setAccessible(true);
            field.set(null, null);
        } catch (Exception e) {
            fail("Failed to reset LazyDnsClient static state: " + e.getMessage());
        }
    }

    @Test
    public void shouldResolveIPv4() {
        List<String> ipv4 = List.of("192.168.0.1");
        when(dnsClient.resolveA(eq("example.com"))).thenReturn(Future.succeededFuture(ipv4));

        LazyDnsClient.lookup(
            executionContext,
            LookupIpVersion.IPV4,
            "example.com",
            result -> {
                assertTrue(result.succeeded());
                assertEquals(ipv4, result.result());
            }
        );

        verify(dnsClient).resolveA("example.com");
    }

    @Test
    public void shouldResolveIPv6() {
        List<String> ipv6 = List.of("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
        when(dnsClient.resolveAAAA(eq("example.com"))).thenReturn(Future.succeededFuture(ipv6));

        LazyDnsClient.lookup(
            executionContext,
            LookupIpVersion.IPV6,
            "example.com",
            result -> {
                assertTrue(result.succeeded());
                assertEquals(ipv6, result.result());
            }
        );

        verify(dnsClient).resolveAAAA("example.com");
    }

    @Test
    public void shouldResolveALL_withIPv4Only() {
        List<String> ipv4 = List.of("192.168.0.1");
        when(dnsClient.resolveA(eq("example.com"))).thenReturn(Future.succeededFuture(ipv4));

        LazyDnsClient.lookup(
            executionContext,
            LookupIpVersion.ALL,
            "example.com",
            result -> {
                assertTrue(result.succeeded());
                assertEquals(ipv4, result.result());
            }
        );

        verify(dnsClient).resolveA("example.com");
        verify(dnsClient, never()).resolveAAAA("example.com");
    }

    @Test
    public void shouldResolveALL_withEmptyIPv4_andUseIPv6() {
        List<String> ipv6 = List.of("2001:abcd::1");
        when(dnsClient.resolveA(eq("example.com"))).thenReturn(Future.succeededFuture(Collections.emptyList()));
        when(dnsClient.resolveAAAA(eq("example.com"))).thenReturn(Future.succeededFuture(ipv6));

        LazyDnsClient.lookup(
            executionContext,
            LookupIpVersion.ALL,
            "example.com",
            result -> {
                assertTrue(result.succeeded());
                assertEquals(ipv6, result.result());
            }
        );

        verify(dnsClient).resolveA("example.com");
        verify(dnsClient).resolveAAAA("example.com");
    }

    @Test
    public void shouldHandleErrorsGracefully() {
        when(dnsClient.resolveA(eq("example.com"))).thenReturn(Future.failedFuture(new RuntimeException("DNS fail")));
        when(dnsClient.resolveAAAA(eq("example.com"))).thenReturn(Future.failedFuture(new RuntimeException("IPv6 also fail")));

        LazyDnsClient.lookup(
            executionContext,
            LookupIpVersion.ALL,
            "example.com",
            result -> {
                assertTrue(result.succeeded());
                assertEquals(Collections.emptyList(), result.result());
            }
        );
    }
}
