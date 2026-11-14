package org.tsicoop.dpdpcms.util;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Set;

/**
 * What may be attached to a grievance: PDF, PNG, JPEG or plain text, up to 5 MB, and the bytes must really be
 * what the declared type says (so a script cannot be uploaded as "application/pdf"). HTML, SVG and anything
 * executable are not on the list.
 */
public final class AttachmentRules {
    private AttachmentRules() {}

    public static final int MAX_BYTES = 5 * 1024 * 1024;
    public static final int MAX_PER_GRIEVANCE = 5;
    private static final Set<String> TYPES = Set.of("application/pdf", "image/png", "image/jpeg", "text/plain");

    /** @return the problem, or null if the file may be stored */
    public static String problem(String fileName, String declaredType, byte[] data) {
        if (data == null || data.length == 0) return "the file is empty";
        if (data.length > MAX_BYTES) return "the file is larger than " + (MAX_BYTES / (1024 * 1024)) + " MB";
        String type = declaredType == null ? "" : declaredType.trim().toLowerCase(Locale.ROOT);
        if (!TYPES.contains(type)) return "file type not allowed (use PDF, PNG, JPEG or plain text)";
        boolean ok;
        switch (type) {
            case "application/pdf": ok = startsWith(data, new byte[]{'%', 'P', 'D', 'F', '-'}); break;
            case "image/png": ok = startsWith(data, new byte[]{(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}); break;
            case "image/jpeg": ok = startsWith(data, new byte[]{(byte) 0xFF, (byte) 0xD8, (byte) 0xFF}); break;
            default: ok = isPlainText(data);
        }
        return ok ? null : "the file content does not match its declared type";
    }

    /** Reject an encoded payload that cannot decode to a permitted size, before spending memory decoding it. */
    public static boolean encodedTooLarge(int base64Length) {
        return base64Length > (MAX_BYTES / 3 + 1) * 4;
    }

    /** Keeps only the last path component and the characters [A-Za-z0-9._-]; never empty, at most 100 chars. */
    public static String safeFileName(String name) {
        if (name == null) return "file";
        String n = name.replace('\\', '/');
        n = n.substring(n.lastIndexOf('/') + 1);
        n = n.replaceAll("[^A-Za-z0-9._-]", "_").replaceAll("_{2,}", "_").replaceAll("_+\\.", ".");
        n = n.replaceAll("^[._]+", "");
        if (n.isEmpty()) return "file";
        if (n.length() > 100) {
            int dot = n.lastIndexOf('.');
            String ext = dot > 0 && n.length() - dot <= 10 ? n.substring(dot) : "";
            n = n.substring(0, 100 - ext.length()) + ext;
        }
        return n;
    }

    private static boolean startsWith(byte[] d, byte[] prefix) {
        if (d.length < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) if (d[i] != prefix[i]) return false;
        return true;
    }

    private static boolean isPlainText(byte[] d) {
        for (byte b : d) if (b == 0) return false;
        try {
            StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(d));
            return true;
        } catch (CharacterCodingException e) {
            return false;
        }
    }
}
