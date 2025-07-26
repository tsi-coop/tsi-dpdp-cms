package org.tsicoop.dpdpcms.framework;

import org.apache.commons.codec.digest.DigestUtils;

import java.nio.charset.StandardCharsets;

public class Crypt {
   private static final String[] DEFAULT_KEYS = {
            "01210ACB39201293948ABE4839201CDF",
            "123219843895AFDE3920291038103839",
            "89128912093908120983980981098309",
            "AABBCCDD019201920384383728298109"};

    private static final char[] hexDigits = {'0', '1', '2', '3', '4', '5',
            '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    private static final boolean updatedProps = false;

    private byte[][] keys = null;

    public Crypt() {
        init(Crypt.DEFAULT_KEYS);
    }

    public Crypt(String[] keystrs) {
        init(keystrs);
    }

    private byte decrypt(byte e, byte[] key) {
        byte d;

        d = e;
        for (int i = key.length - 1; i >= 0; i--) {
            d = (byte) ((int) d ^ (int) key[i]);
        }

        return d;
    }

    public String decrypt(String ectstr) {
        byte[] ect = null;
        int size;
        byte[] origBytes = null;
        String dctStr = null;

        ect = fromString(ectstr);
        origBytes = new byte[ect.length];
        for (int i = 0; i < origBytes.length; i += keys.length) {
            for (int j = 0; j < keys.length; j++) {
                if ((i + j) >= origBytes.length) {
                    break;
                } else {
                    origBytes[i + j] = decrypt(ect[i + j], keys[j]);
                }
            }
        }

        dctStr = new String(origBytes, StandardCharsets.UTF_8);
        return dctStr;
    }

    private byte encrypt(byte d, byte[] key) {
        byte e;

        e = d;
        for (int i = 0; i < key.length; i++) {
            e = (byte) ((int) e ^ (int) key[i]);
        }

        return e;
    }

    public String encrypt(String orig) {
        byte[] ect = null;
        int size;
        byte[] origBytes = null;

        origBytes = orig.getBytes(StandardCharsets.UTF_8);

        ect = new byte[origBytes.length];
        for (int i = 0; i < origBytes.length; i += keys.length) {
            for (int j = 0; j < keys.length; j++) {
                if ((i + j) >= origBytes.length) {
                    break;
                } else {
                    ect[i + j] = encrypt(origBytes[i + j], keys[j]);
                }
            }
        }
        return toString(ect);
    }

    private int fromDigit(char ch) {
        if (ch >= '0' && ch <= '9')
            return ch - '0';
        if (ch >= 'A' && ch <= 'F')
            return ch - 'A' + 10;
        if (ch >= 'a' && ch <= 'f')
            return ch - 'a' + 10;

        throw new IllegalArgumentException("invalid hex digit '" + ch + "'");
    }

    private byte[] fromString(String hex) {
        int len = hex.length();
        byte[] buf = new byte[((len + 1) / 2)];

        int i = 0, j = 0;
        if ((len % 2) == 1)
            buf[j++] = (byte) fromDigit(hex.charAt(i++));

        while (i < len) {
            buf[j++] = (byte) ((fromDigit(hex.charAt(i++)) << 4) | fromDigit(hex
                    .charAt(i++)));
        }
        return buf;
    }

    private void init(String[] keystrs) {
        keys = new byte[keystrs.length][];
        for (int i = 0; i < keys.length; i++) {
            keys[i] = fromString(keystrs[i]);
        }
    }

    private String toString(byte[] ba) {
        char[] buf = new char[ba.length * 2];
        int j = 0;
        int k;

        for (int i = 0; i < ba.length; i++) {
            k = ba[i];
            buf[j++] = hexDigits[(k >>> 4) & 0x0F];
            buf[j++] = hexDigits[k & 0x0F];
        }
        return new String(buf);
    }

    public static String getToken(String input) {
        String token = null;
        token = DigestUtils.md5Hex(input + System.nanoTime());
        return token;
    }

    public static void main(String[] args) throws Exception {
        Crypt crypt = null;
        String orig = null;
        crypt = new Crypt();
        String ect = "241D44742603";
        System.out.println("dct = " + crypt.decrypt(ect));
    }

}


