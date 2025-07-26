package org.tsicoop.dpdpcms.framework;

import org.apache.commons.codec.binary.StringUtils;

import java.nio.charset.StandardCharsets;

public class Base64 {
	
	public static byte[] encode(String str) {
		return org.apache.commons.codec.binary.Base64.encodeBase64(str.getBytes(StandardCharsets.UTF_8));
	}

	public static String encodeToString(String str) {
		return StringUtils.newStringUtf8(org.apache.commons.codec.binary.Base64.encodeBase64(str.getBytes(StandardCharsets.UTF_8)));
	}

	public static byte[] encode(byte[] bytes) {
		return org.apache.commons.codec.binary.Base64.encodeBase64(bytes);
	}

	public static String encodeToString(byte[] bytes) {
		return StringUtils.newStringUtf8(org.apache.commons.codec.binary.Base64.encodeBase64(bytes));
	}
	
	public static byte[] encodeURLSafeString(String str) {
		return org.apache.commons.codec.binary.Base64.encodeBase64URLSafe(str.getBytes(StandardCharsets.UTF_8));
	}

	public static String encodeToStringURLSafeString(String str) {
		return org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(str.getBytes(StandardCharsets.UTF_8));
	}

	public static byte[] encodeURLSafeString(byte[] bytes) {
		return org.apache.commons.codec.binary.Base64.encodeBase64URLSafe(bytes);
	}

	public static String encodeToStringURLSafeString(byte[] bytes) {
		return org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(bytes);
	}

	public static String decodeToString(String str) {
		return new String(org.apache.commons.codec.binary.Base64.decodeBase64(str));
	}
	
	public static byte[] decode(String str) {
		return org.apache.commons.codec.binary.Base64.decodeBase64(str);
	}
	
}
