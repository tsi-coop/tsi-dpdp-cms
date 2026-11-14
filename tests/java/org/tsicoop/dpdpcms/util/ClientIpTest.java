package org.tsicoop.dpdpcms.util;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ClientIpTest {
    private static final List<String> PROXIES = List.of("10.0.0.5", "10.0.0.6");

    @Test void noTrustedProxyMeansTheSocketAddressIsTheClient() {
        assertEquals("203.0.113.9", ClientIp.resolve("203.0.113.9", "1.2.3.4", List.of()));
    }

    @Test void forwardedHeaderIsIgnoredWhenTheSenderIsNotATrustedProxy() {
        assertEquals("198.51.100.7", ClientIp.resolve("198.51.100.7", "1.2.3.4", PROXIES));
    }

    @Test void trustedProxyPassesOnTheClientAddress() {
        assertEquals("203.0.113.9", ClientIp.resolve("10.0.0.5", "203.0.113.9", PROXIES));
    }

    @Test void clientCannotForgeAnAddressByPrependingToTheHeader() {
        // client sent "X-Forwarded-For: 6.6.6.6"; the proxy appended the real peer
        assertEquals("203.0.113.9", ClientIp.resolve("10.0.0.5", "6.6.6.6, 203.0.113.9", PROXIES));
    }

    @Test void chainOfTrustedProxiesIsWalkedFromTheRight() {
        assertEquals("203.0.113.9", ClientIp.resolve("10.0.0.5", "203.0.113.9, 10.0.0.6", PROXIES));
    }

    @Test void missingOrBlankHeaderFallsBackToTheSocketAddress() {
        assertEquals("10.0.0.5", ClientIp.resolve("10.0.0.5", null, PROXIES));
        assertEquals("10.0.0.5", ClientIp.resolve("10.0.0.5", "  ", PROXIES));
    }

    @Test void allTrustedMeansTheLeftmostEntry() {
        assertEquals("10.0.0.6", ClientIp.resolve("10.0.0.5", "10.0.0.6", PROXIES));
    }

    @Test void garbageEntriesAreNotAccepted() {
        assertEquals("10.0.0.5", ClientIp.resolve("10.0.0.5", "not-an-ip", PROXIES));
        assertEquals("203.0.113.9", ClientIp.resolve("10.0.0.5", "not-an-ip, 203.0.113.9", PROXIES));
    }

    @Test void trustedProxyListParsesCommasAndBlanks() {
        assertEquals(List.of("10.0.0.5", "10.0.0.6"), ClientIp.parseTrusted(" 10.0.0.5 , ,10.0.0.6 "));
        assertEquals(List.of(), ClientIp.parseTrusted(null));
        assertEquals(List.of(), ClientIp.parseTrusted(""));
    }

    @Test void ipv6AddressesWork() {
        assertEquals("2001:db8::1", ClientIp.resolve("::1", "2001:db8::1", List.of("::1")));
    }
}
