package org.tsicoop.dpdpcms.framework;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class KmsService {

    private final KmsClient kmsClient;
    private final String kmsKeyId; // KMS Key ARN or Alias ARN
    private byte[] masterAESTransientKey; // Conceptual: Stores a master AES key loaded from KMS once

    private static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int IV_LENGTH = 16; // 16 bytes for AES CBC

    public KmsService(String region, String kmsKeyId) {
        this.kmsClient = KmsClient.builder()
                .region(Region.of(region))
                .build();
        this.kmsKeyId = kmsKeyId;
        // In a real scenario, you'd load this master key securely on startup
        // using generateDataKey or decryptDataKey of a stored encrypted master data key.
        // For simplicity in this example, it's a placeholder.
        // Example: loadMasterAESTransientKey();
    }

    // Conceptual method to load a master AES key from KMS at application startup
    // In production, this key should itself be encrypted by KMS and only decrypted here once.
    // For this example, we'll simulate generating it once.
    public void loadMasterAESTransientKey() {
        if (masterAESTransientKey == null) {
            System.out.println("KmsService: Loading master AES key for client-side encryption...");
            try {
                // Generate a data key from KMS to be used as our master AES key
                GenerateDataKeyResponse response = kmsClient.generateDataKey(GenerateDataKeyRequest.builder()
                        .keyId(kmsKeyId)
                        .keySpec(DataKeySpec.AES_256)
                        .build());
                this.masterAESTransientKey = response.plaintext().asByteArray();
                // WARNING: The encrypted counterpart (response.ciphertextBlob()) should be stored
                // and the plaintext used only temporarily in memory for real envelope encryption.
                // This is a simplification for the 'master key once' scenario.
                System.out.println("KmsService: Master AES key loaded successfully.");
            } catch (KmsException e) {
                System.err.println("KmsService: Error loading master AES key from KMS: " + e.getMessage());
                // In production, this should be a critical startup failure
                throw new RuntimeException("Failed to load master AES key from KMS", e);
            }
        }
    }

    public byte[] getMasterAESTransientKey() {
        if (masterAESTransientKey == null) {
            // Attempt to load if not already loaded (e.g., lazy loading)
            loadMasterAESTransientKey();
        }
        return masterAESTransientKey;
    }


    /**
     * Encrypts plaintext data using an AWS KMS Customer Managed Key (CMK).
     * KMS will encrypt the data directly, returning ciphertext. (Up to 4KB)
     *
     * @param plaintext The data to encrypt.
     * @param encryptionContext Optional additional authenticated data.
     * @return Base64 encoded ciphertext.
     */
    public String encryptDataWithKms(String plaintext, Map<String, String> encryptionContext) {
        try {
            EncryptRequest encryptRequest = EncryptRequest.builder()
                    .keyId(kmsKeyId)
                    .plaintext(SdkBytes.fromString(plaintext, StandardCharsets.UTF_8))
                    .encryptionContext(encryptionContext)
                    .build();

            EncryptResponse encryptResponse = kmsClient.encrypt(encryptRequest);
            return Base64.getEncoder().encodeToString(encryptResponse.ciphertextBlob().asByteArray());

        } catch (KmsException e) {
            System.err.println("KMS Encryption Error: " + e.getMessage());
            throw new RuntimeException("Failed to encrypt data with KMS", e);
        }
    }

    /**
     * Decrypts ciphertext data using an AWS KMS Customer Managed Key (CMK).
     * KMS will decrypt the ciphertext directly, returning plaintext.
     *
     * @param ciphertextBase64 The Base64 encoded ciphertext to decrypt.
     * @param encryptionContext Optional additional authenticated data (must match encryption context).
     * @return Decrypted plaintext.
     */
    public String decryptDataWithKms(String ciphertextBase64, Map<String, String> encryptionContext) {
        try {
            byte[] ciphertextBytes = Base64.getDecoder().decode(ciphertextBase64);

            DecryptRequest decryptRequest = DecryptRequest.builder()
                    .ciphertextBlob(SdkBytes.fromByteArray(ciphertextBytes))
                    .encryptionContext(encryptionContext)
                    .build();

            DecryptResponse decryptResponse = kmsClient.decrypt(decryptRequest);
            return decryptResponse.plaintext().asString(StandardCharsets.UTF_8);

        } catch (KmsException e) {
            System.err.println("KMS Decryption Error: " + e.getMessage());
            throw new RuntimeException("Failed to decrypt data with KMS", e);
        }
    }

    /**
     * Generates a unique data key (plaintext and encrypted) using KMS.
     * The plaintext data key is used by your application for local encryption/decryption (e.g., with AES).
     * The encrypted data key is stored alongside your encrypted data.
     *
     * @return A map containing "plaintextDataKey" (Base64 encoded) and "encryptedDataKey" (Base64 encoded).
     */
    public Map<String, String> generateDataKey() {
        try {
            GenerateDataKeyRequest generateDataKeyRequest = GenerateDataKeyRequest.builder()
                    .keyId(kmsKeyId)
                    .keySpec(DataKeySpec.AES_256) // Request an AES-256 key
                    .build();

            GenerateDataKeyResponse response = kmsClient.generateDataKey(generateDataKeyRequest);

            Map<String, String> keys = new HashMap<>();
            keys.put("plaintextDataKey", Base64.getEncoder().encodeToString(response.plaintext().asByteArray()));
            keys.put("encryptedDataKey", Base64.getEncoder().encodeToString(response.ciphertextBlob().asByteArray()));
            return keys;

        } catch (KmsException e) {
            System.err.println("KMS GenerateDataKey Error: " + e.getMessage());
            throw new RuntimeException("Failed to generate data key with KMS", e);
        }
    }

    /**
     * Decrypts an encrypted data key using KMS.
     * This is used when you retrieve an encrypted data key (stored with your encrypted data)
     * and need its plaintext version for client-side decryption.
     *
     * @param encryptedDataKeyBase64 The Base64 encoded encrypted data key.
     * @return The plaintext data key (Base64 encoded).
     */
    public String decryptDataKey(String encryptedDataKeyBase64) {
        try {
            byte[] encryptedDataKeyBytes = Base64.getDecoder().decode(encryptedDataKeyBase64);

            DecryptRequest decryptRequest = DecryptRequest.builder()
                    .ciphertextBlob(SdkBytes.fromByteArray(encryptedDataKeyBytes))
                    .keyId(kmsKeyId) // Specify the CMK that encrypted the data key
                    .build();

            DecryptResponse response = kmsClient.decrypt(decryptRequest);
            return Base64.getEncoder().encodeToString(response.plaintext().asByteArray());

        } catch (KmsException e) {
            System.err.println("KMS DecryptDataKey Error: " + e.getMessage());
            throw new RuntimeException("Failed to decrypt data key with KMS", e);
        }
    }

    public void close() {
        if (kmsClient != null) {
            kmsClient.close();
        }
    }

    // --- Client-Side AES Encryption/Decryption using a Plaintext Data Key ---
    // (This part is used by your application for actual sensitive data encryption/decryption)

    public byte[] aesEncrypt(byte[] data, byte[] plaintextAesKey) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(plaintextAesKey, "AES");
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[IV_LENGTH];
        secureRandom.nextBytes(iv); // Generate a random IV for each encryption

        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

        byte[] encryptedData = cipher.doFinal(data);
        // This 'encryptedData' should always be a multiple of 16 if padding is used.
        System.out.println("DEBUG_ENCRYPT: Ciphertext length before IV prepend: " + encryptedData.length); // ADD THIS

        // Prepend IV to encrypted data so it can be used for decryption
        byte[] encryptedDataWithIv = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, encryptedDataWithIv, 0, iv.length);
        System.arraycopy(encryptedData, 0, encryptedDataWithIv, iv.length, encryptedData.length);
        System.out.println("DEBUG_ENCRYPT: Final blob length (IV+Ciphertext): " + encryptedDataWithIv.length); // ADD THIS
        return encryptedDataWithIv;
    }

    public byte[] aesDecrypt(byte[] encryptedDataWithIv, byte[] plaintextAesKey) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(plaintextAesKey, "AES");

        byte[] iv = Arrays.copyOfRange(encryptedDataWithIv, 0, IV_LENGTH);
        byte[] encryptedData = Arrays.copyOfRange(encryptedDataWithIv, IV_LENGTH, encryptedDataWithIv.length);

        System.out.println("DEBUG: encryptedDataWithIv length: " + encryptedDataWithIv.length);

        System.out.println("DEBUG: IV length: " + iv.length);

        System.out.println("DEBUG: Ciphertext length (after IV extraction): " + encryptedData.length);

        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

        return cipher.doFinal(encryptedData);
    }

    public static void main(String[] args) {
        // IMPORTANT: Replace with your actual AWS Region and KMS Key ID/ARN/Alias!
        // The KMS Key ID can be the Key ARN (e.g., arn:aws:kms:us-east-1:123456789012:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
        // or an alias ARN (e.g., "alias/your-alias-name").
        String awsRegion = "ap-south-1"; // Example: Mumbai region
        String kmsKeyIdentifier = "arn:aws:kms:ap-south-1:522814729587:key/0ceea301-bb7f-4aab-8381-2702413ccae1"; // Replace with YOUR KMS key alias or ARN

        KmsService kmsService = null; // Initialize to null for finally block
        try {
            kmsService = new KmsService(awsRegion, kmsKeyIdentifier);

            // 1. Load the master AES transient key from KMS (as assumed by the Vault class)
            System.out.println("--- Loading Master AES Key ---");
            kmsService.loadMasterAESTransientKey(); // This populates masterAESTransientKey

            byte[] masterKey = kmsService.getMasterAESTransientKey();
            if (masterKey == null) {
                System.err.println("Failed to load master AES key. Exiting test.");
                return;
            }
            System.out.println("Master AES Key loaded (length: " + masterKey.length + " bytes)");

            // --- Test Case 1: Client-Side AES Encryption/Decryption ---
            System.out.println("\n--- Testing Client-Side AES Encryption/Decryption ---");
            String originalSensitiveData = "This is a sensitive Aadhaar number: 1234 5678 9012. It should be kept secret.";

            // Encrypt using the master AES key
            byte[] encryptedDataBytes = kmsService.aesEncrypt(originalSensitiveData.getBytes(StandardCharsets.UTF_8), masterKey);
            String encryptedDataB64 = Base64.getEncoder().encodeToString(encryptedDataBytes);
            System.out.println("Original Data: " + originalSensitiveData);
            System.out.println("Encrypted Data (Base64): " + encryptedDataB64);

            // Decrypt using the same master AES key
            byte[] decryptedDataBytes = kmsService.aesDecrypt(encryptedDataBytes, masterKey);
            String decryptedData = new String(decryptedDataBytes, StandardCharsets.UTF_8);
            System.out.println("Decrypted Data: " + decryptedData);
            System.out.println("Data Match: " + originalSensitiveData.equals(decryptedData));


            // --- Test Case 2: Direct KMS Encryption/Decryption (for comparison, though not primary for Vault data) ---
            System.out.println("\n--- Testing Direct KMS Encryption/Decryption (for small data <= 4KB) ---");
            String smallSecret = "My small secret";
            Map<String, String> encryptionContext = new HashMap<>();
            encryptionContext.put("app_id", "TSI_Vault_Plus");
            encryptionContext.put("data_type", "small_secret");

            String kmsEncryptedB64 = kmsService.encryptDataWithKms(smallSecret, encryptionContext);
            System.out.println("Original Small Secret: " + smallSecret);
            System.out.println("KMS Encrypted (Base64): " + kmsEncryptedB64);

            String kmsDecrypted = kmsService.decryptDataWithKms(kmsEncryptedB64, encryptionContext);
            System.out.println("KMS Decrypted: " + kmsDecrypted);
            System.out.println("Small Secret Match: " + smallSecret.equals(kmsDecrypted));


            // --- Test Case 3: Generate and Decrypt Data Key (Envelope Encryption Pattern) ---
            System.out.println("\n--- Testing KMS GenerateDataKey and DecryptDataKey (Envelope Encryption) ---");
            Map<String, String> generatedKeys = kmsService.generateDataKey();
            String plaintextGeneratedKeyB64 = generatedKeys.get("plaintextDataKey");
            String encryptedGeneratedKeyB64 = generatedKeys.get("encryptedDataKey");

            System.out.println("Generated Plaintext Data Key (Base64): " + plaintextGeneratedKeyB64);
            System.out.println("Generated Encrypted Data Key (Base64): " + encryptedGeneratedKeyB64);

            String decryptedGeneratedKeyB64 = kmsService.decryptDataKey(encryptedGeneratedKeyB64);
            System.out.println("Decrypted Plaintext Data Key (Base64): " + decryptedGeneratedKeyB64);
            System.out.println("Generated Key Match: " + plaintextGeneratedKeyB64.equals(decryptedGeneratedKeyB64));

        } catch (Exception e) {
            System.err.println("\nAn error occurred during KMS service test:");
            e.printStackTrace();
        } finally {
            if (kmsService != null) {
                kmsService.close(); // Close the KMS client
                System.out.println("\nKmsClient closed.");
            }
        }
    }
}