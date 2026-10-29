
package com.ruchitha.encryption.service;

import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class FileEncryptionServiceTest {

    private final FileEncryptionService service =
            new FileEncryptionService();

    private final char[] password =
            "MySecurePassword@123!".toCharArray();

    @Test
    void encryptAndDecryptShouldReturnOriginalData()
            throws GeneralSecurityException {

        byte[] originalData =
                "Hello, this is my Ruchitha project!"
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8);

        byte[] encryptedData =
                service.encrypt(originalData, password);

        byte[] decryptedData =
                service.decrypt(encryptedData, password);

        assertArrayEquals(originalData, decryptedData);
    }

    @Test
    void decryptWithWrongPasswordShouldFail()
            throws GeneralSecurityException {

        byte[] originalData =
                "Confidential file".getBytes(
                        java.nio.charset.StandardCharsets.UTF_8);

        byte[] encryptedData =
                service.encrypt(originalData, password);

        char[] wrongPassword = "WrongPassword123!".toCharArray();

        assertThrows(
                GeneralSecurityException.class,
                () -> service.decrypt(encryptedData, wrongPassword)
        );
    }

    @Test
    void modifiedEncryptedFileShouldFailDecryption()
            throws GeneralSecurityException {

        byte[] originalData =
                "Important document".getBytes(
                        java.nio.charset.StandardCharsets.UTF_8);

        byte[] encryptedData =
                service.encrypt(originalData, password);

        // Modify the final byte to simulate tampering.
        encryptedData[encryptedData.length - 1] ^= 1;

        assertThrows(
                GeneralSecurityException.class,
                () -> service.decrypt(encryptedData, password)
        );
    }

    @Test
    void invalidEncryptedFileShouldFailDecryption() {

        byte[] invalidData = {1, 2, 3, 4, 5};

        assertThrows(
                GeneralSecurityException.class,
                () -> service.decrypt(invalidData, password)
        );
    }

    @Test
    void emptyFileShouldEncryptAndDecryptSuccessfully()
            throws GeneralSecurityException {

        byte[] originalData = new byte[0];

        byte[] encryptedData =
                service.encrypt(originalData, password);

        byte[] decryptedData =
                service.decrypt(encryptedData, password);

        assertArrayEquals(originalData, decryptedData);
    }

    @Test
    void encryptingSameDataTwiceShouldProduceDifferentResults()
            throws GeneralSecurityException {

        byte[] originalData =
                "Same file content".getBytes(
                        java.nio.charset.StandardCharsets.UTF_8);

        byte[] firstEncryption =
                service.encrypt(originalData, password);

        byte[] secondEncryption =
                service.encrypt(originalData, password);

        assertFalse(Arrays.equals(
                firstEncryption, secondEncryption));
    }

    @Test
    void emptyPasswordShouldBeRejected() {

        byte[] originalData =
                "Test data".getBytes(
                        java.nio.charset.StandardCharsets.UTF_8);

        char[] emptyPassword = new char[0];

        assertThrows(
                IllegalArgumentException.class,
                () -> service.encrypt(originalData, emptyPassword)
        );
    }
}
