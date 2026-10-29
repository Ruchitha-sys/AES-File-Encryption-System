package com.ruchitha.encryption.controller;

import com.ruchitha.encryption.service.FileEncryptionService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.security.GeneralSecurityException;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(FileEncryptionController.class)
class FileEncryptionControllerTest {

    private static final String STRONG_PASSWORD = "StrongPassword@123";

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private FileEncryptionService encryptionService;

    private MockMultipartFile textFile(String name) {
        return new MockMultipartFile(
                "file", name, MediaType.TEXT_PLAIN_VALUE, "Hello World".getBytes());
    }

    private MockMultipartFile binaryFile(String name) {
        return new MockMultipartFile(
                "file", name, MediaType.APPLICATION_OCTET_STREAM_VALUE, "encrypted-data".getBytes());
    }

    // ---------------- ENCRYPT ----------------

    // Test 1: Successful encryption
    @Test
    void testEncryptFileSuccessfully() throws Exception {
        byte[] encryptedData = "encrypted-data".getBytes();

        when(encryptionService.encrypt(any(byte[].class), any(char[].class)))
                .thenReturn(encryptedData);

        mockMvc.perform(multipart("/api/files/encrypt")
                        .file(textFile("test.txt"))
                        .param("password", STRONG_PASSWORD))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_OCTET_STREAM))
                .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION,
                        containsString("test.txt.enc")))
                .andExpect(content().bytes(encryptedData));

        verify(encryptionService).encrypt(any(byte[].class), any(char[].class));
    }

    // Test 2: Missing password
    @Test
    void testEncryptWithoutPassword() throws Exception {
        mockMvc.perform(multipart("/api/files/encrypt")
                        .file(textFile("test.txt")))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("Please enter a password."));

        verifyNoInteractions(encryptionService);
    }

    // Test 3: Blank password
    @Test
    void testEncryptWithBlankPassword() throws Exception {
        mockMvc.perform(multipart("/api/files/encrypt")
                        .file(textFile("test.txt"))
                        .param("password", "   "))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("Please enter a password."));

        verifyNoInteractions(encryptionService);
    }

    // Test 4: Missing file
    @Test
    void testEncryptWithoutFile() throws Exception {
        mockMvc.perform(multipart("/api/files/encrypt")
                        .param("password", STRONG_PASSWORD))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("Please choose a file to encrypt."));

        verifyNoInteractions(encryptionService);
    }

    // Test 5: Empty file
    @Test
    void testEncryptWithEmptyFile() throws Exception {
        MockMultipartFile emptyFile = new MockMultipartFile(
                "file", "empty.txt", MediaType.TEXT_PLAIN_VALUE, new byte[0]);

        mockMvc.perform(multipart("/api/files/encrypt")
                        .file(emptyFile)
                        .param("password", STRONG_PASSWORD))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("Please choose a file to encrypt."));

        verifyNoInteractions(encryptionService);
    }

    // Test 6: Weak password rejected by the service
    @Test
    void testEncryptWithWeakPassword() throws Exception {
        when(encryptionService.encrypt(any(byte[].class), any(char[].class)))
                .thenThrow(new IllegalArgumentException("Password must contain a number."));

        mockMvc.perform(multipart("/api/files/encrypt")
                        .file(textFile("test.txt"))
                        .param("password", "weak"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("Password must contain a number."));
    }

    // Test 7: Encryption failure inside the service
    @Test
    void testEncryptWithSecurityException() throws Exception {
        when(encryptionService.encrypt(any(byte[].class), any(char[].class)))
                .thenThrow(new GeneralSecurityException("boom"));

        mockMvc.perform(multipart("/api/files/encrypt")
                        .file(textFile("test.txt"))
                        .param("password", STRONG_PASSWORD))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("Encryption failed."));
    }

    // ---------------- DECRYPT ----------------

    // Test 8: Successful decryption, ".enc" is stripped from the filename
    @Test
    void testDecryptFileSuccessfully() throws Exception {
        byte[] decryptedData = "Hello World".getBytes();

        when(encryptionService.decrypt(any(byte[].class), any(char[].class)))
                .thenReturn(decryptedData);

        mockMvc.perform(multipart("/api/files/decrypt")
                        .file(binaryFile("test.txt.enc"))
                        .param("password", STRONG_PASSWORD))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_OCTET_STREAM))
                .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION,
                        containsString("test.txt")))
                .andExpect(content().bytes(decryptedData));

        verify(encryptionService).decrypt(any(byte[].class), any(char[].class));
    }

    // Test 9: File without ".enc" gets a "decrypted-" prefix
    @Test
    void testDecryptFileWithoutEncExtension() throws Exception {
        when(encryptionService.decrypt(any(byte[].class), any(char[].class)))
                .thenReturn("Hello World".getBytes());

        mockMvc.perform(multipart("/api/files/decrypt")
                        .file(binaryFile("secret.bin"))
                        .param("password", STRONG_PASSWORD))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION,
                        containsString("decrypted-secret.bin")));
    }

    // Test 10: Missing password on decrypt
    @Test
    void testDecryptWithoutPassword() throws Exception {
        mockMvc.perform(multipart("/api/files/decrypt")
                        .file(binaryFile("test.txt.enc")))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("Please enter a password."));

        verifyNoInteractions(encryptionService);
    }

    // Test 11: Missing file on decrypt
    @Test
    void testDecryptWithoutFile() throws Exception {
        mockMvc.perform(multipart("/api/files/decrypt")
                        .param("password", STRONG_PASSWORD))
                .andExpect(status().isBadRequest())
                .andExpect(content().string("Please choose a file to decrypt."));

        verifyNoInteractions(encryptionService);
    }

    // Test 12: Wrong password or corrupted/tampered ciphertext
    @Test
    void testDecryptWithInvalidCiphertext() throws Exception {
        when(encryptionService.decrypt(any(byte[].class), any(char[].class)))
                .thenThrow(new GeneralSecurityException("Decryption failed"));

        mockMvc.perform(multipart("/api/files/decrypt")
                        .file(binaryFile("corrupted.enc"))
                        .param("password", "WrongPassword"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("Decryption failed!")));
    }
}