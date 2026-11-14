package org.tsicoop.dpdpcms.util;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class GrievanceRulesTest {

    // ---- status + resolution summary ----
    @Test void onlyKnownStatusesAreAccepted() {
        for (String s : new String[]{"NEW", "IN_PROGRESS", "RESOLVED", "CLOSED", "ESCALATED", "resolved"})
            assertTrue(GrievanceRules.isKnownStatus(s), s);
        assertFalse(GrievanceRules.isKnownStatus("DONE"));
        assertFalse(GrievanceRules.isKnownStatus(null));
        assertFalse(GrievanceRules.isKnownStatus(""));
    }

    @Test void resolvedOrClosedNeedsARealSummary() {
        assertNotNull(GrievanceRules.resolutionProblem("RESOLVED", null));
        assertNotNull(GrievanceRules.resolutionProblem("RESOLVED", "   "));
        assertNotNull(GrievanceRules.resolutionProblem("closed", "too short"));   // 9 chars
        assertNull(GrievanceRules.resolutionProblem("RESOLVED", "Corrected the record and confirmed."));
        assertNull(GrievanceRules.resolutionProblem("CLOSED", "  exactly 10  "));  // trimmed length counts
    }

    @Test void otherStatusesNeedNoSummary() {
        assertNull(GrievanceRules.resolutionProblem("IN_PROGRESS", null));
        assertNull(GrievanceRules.resolutionProblem("ESCALATED", ""));
    }

    // ---- channel ----
    @Test void principalTokenAlwaysMeansPortalWhateverIsClaimed() {
        assertEquals("PRINCIPAL_PORTAL", GrievanceRules.channel(true, "PHONE", "API_INTEGRATION"));
    }

    @Test void otherCallersMayNameASupportedChannelElseGetTheDefault() {
        assertEquals("PHONE", GrievanceRules.channel(false, "phone", "API_INTEGRATION"));
        assertEquals("EMAIL", GrievanceRules.channel(false, "EMAIL", "OPERATOR_CONSOLE"));
        assertEquals("API_INTEGRATION", GrievanceRules.channel(false, null, "API_INTEGRATION"));
        assertEquals("OPERATOR_CONSOLE", GrievanceRules.channel(false, "", "OPERATOR_CONSOLE"));
    }

    @Test void anUnsupportedChannelIsRefused() {
        assertNull(GrievanceRules.channel(false, "CARRIER_PIGEON", "API_INTEGRATION"));
        assertNull(GrievanceRules.channel(false, "PRINCIPAL_PORTAL", "API_INTEGRATION")); // only a principal token earns this
    }

    // ---- reference number ----
    @Test void referenceNumbersAreReadableAndOrdered() {
        assertEquals("GRV-2026-000042", GrievanceRules.referenceNumber(2026, 42));
        assertEquals("GRV-2026-123456", GrievanceRules.referenceNumber(2026, 123456));
    }

    // ---- feedback ----
    @Test void ratingMustBeAWholeNumberFromOneToFive() {
        assertNull(GrievanceRules.feedbackProblem(1L, null));
        assertNull(GrievanceRules.feedbackProblem(5L, "thanks"));
        assertNotNull(GrievanceRules.feedbackProblem(0L, null));
        assertNotNull(GrievanceRules.feedbackProblem(6L, null));
        assertNotNull(GrievanceRules.feedbackProblem("5", null));
        assertNotNull(GrievanceRules.feedbackProblem(3.5, null));
        assertNotNull(GrievanceRules.feedbackProblem(null, null));
    }

    @Test void feedbackCommentIsBounded() {
        char[] big = new char[1001]; Arrays.fill(big, 'x');
        assertNotNull(GrievanceRules.feedbackProblem(3L, new String(big)));
        char[] ok = new char[1000]; Arrays.fill(ok, 'x');
        assertNull(GrievanceRules.feedbackProblem(3L, new String(ok)));
    }

    // ---- attachments ----
    private static byte[] pdf() { return "%PDF-1.7 hello".getBytes(StandardCharsets.US_ASCII); }
    private static byte[] png() { return new byte[]{(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0}; }
    private static byte[] jpg() { return new byte[]{(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0, 0, 0}; }

    @Test void allowedTypesWithMatchingContentPass() {
        assertNull(AttachmentRules.problem("a.pdf", "application/pdf", pdf()));
        assertNull(AttachmentRules.problem("a.png", "image/png", png()));
        assertNull(AttachmentRules.problem("a.jpg", "image/jpeg", jpg()));
        assertNull(AttachmentRules.problem("a.txt", "text/plain", "plain words".getBytes(StandardCharsets.UTF_8)));
    }

    @Test void aDeclaredTypeThatDoesNotMatchTheBytesIsRefused() {
        assertNotNull(AttachmentRules.problem("evil.pdf", "application/pdf", "<html><script>alert(1)</script>".getBytes(StandardCharsets.US_ASCII)));
        assertNotNull(AttachmentRules.problem("a.png", "image/png", pdf()));
        assertNotNull(AttachmentRules.problem("a.txt", "text/plain", new byte[]{'a', 0, 'b'}));
    }

    @Test void typesOutsideTheAllowListAreRefused() {
        assertNotNull(AttachmentRules.problem("a.html", "text/html", "<p>x</p>".getBytes(StandardCharsets.US_ASCII)));
        assertNotNull(AttachmentRules.problem("a.svg", "image/svg+xml", "<svg/>".getBytes(StandardCharsets.US_ASCII)));
        assertNotNull(AttachmentRules.problem("a.exe", "application/octet-stream", new byte[]{'M', 'Z'}));
        assertNotNull(AttachmentRules.problem("a", null, pdf()));
    }

    @Test void emptyAndOversizedFilesAreRefused() {
        assertNotNull(AttachmentRules.problem("a.pdf", "application/pdf", new byte[0]));
        byte[] big = new byte[AttachmentRules.MAX_BYTES + 1];
        System.arraycopy(pdf(), 0, big, 0, pdf().length);
        assertNotNull(AttachmentRules.problem("a.pdf", "application/pdf", big));
        byte[] atLimit = new byte[AttachmentRules.MAX_BYTES];
        System.arraycopy(pdf(), 0, atLimit, 0, pdf().length);
        assertNull(AttachmentRules.problem("a.pdf", "application/pdf", atLimit));
    }

    @Test void encodedSizeIsCheckedBeforeDecoding() {
        assertTrue(AttachmentRules.encodedTooLarge(AttachmentRules.MAX_BYTES * 2));
        assertFalse(AttachmentRules.encodedTooLarge(1000));
    }

    @Test void fileNamesAreReducedToSafeCharacters() {
        assertEquals("passwd", AttachmentRules.safeFileName("../../etc/passwd"));
        assertEquals("evil.pdf", AttachmentRules.safeFileName("C:\\temp\\evil.pdf"));
        assertEquals("my_file_1.pdf", AttachmentRules.safeFileName("my file<1>.pdf"));
        assertEquals("file", AttachmentRules.safeFileName(""));
        assertEquals("file", AttachmentRules.safeFileName(null));
        assertTrue(AttachmentRules.safeFileName("x".repeat(300) + ".pdf").length() <= 100);
    }
}
