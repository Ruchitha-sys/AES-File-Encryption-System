package com.ruchitha.encryption.controller;

import com.ruchitha.encryption.service.FileEncryptionService;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

@RestController
@RequestMapping("/api/files")
public class FileEncryptionController {

    private final FileEncryptionService encryptionService;

    public FileEncryptionController(FileEncryptionService encryptionService) {
        this.encryptionService = encryptionService;
    }

    @PostMapping("/encrypt")
    public ResponseEntity<byte[]> encryptFile(
            @RequestParam(value = "file", required = false) MultipartFile file,
            @RequestParam(value = "password", required = false) String password)
            throws IOException {

        if (file == null || file.isEmpty()) {
            return error("Please choose a file to encrypt.");
        }
        if (password == null || password.isBlank()) {
            return error("Please enter a password.");
        }

        char[] passwordChars = password.toCharArray();
        try {
            byte[] encryptedData = encryptionService.encrypt(file.getBytes(), passwordChars);

            String name = file.getOriginalFilename();
            if (name == null || name.isBlank()) {
                name = "encrypted-file";
            }
            return download(encryptedData, name + ".enc");

        } catch (IllegalArgumentException e) {
            return error(e.getMessage());
        } catch (GeneralSecurityException e) {
            return error("Encryption failed.");
        } finally {
            Arrays.fill(passwordChars, '\0');
        }
    }

    @PostMapping("/decrypt")
    public ResponseEntity<byte[]> decryptFile(
            @RequestParam(value = "file", required = false) MultipartFile file,
            @RequestParam(value = "password", required = false) String password)
            throws IOException {

        if (file == null || file.isEmpty()) {
            return error("Please choose a file to decrypt.");
        }
        if (password == null || password.isBlank()) {
            return error("Please enter a password.");
        }

        char[] passwordChars = password.toCharArray();
        try {
            byte[] decryptedData = encryptionService.decrypt(file.getBytes(), passwordChars);

            String name = file.getOriginalFilename();
            if (name == null || name.isBlank()) {
                name = "decrypted-file";
            }
            if (name.endsWith(".enc")) {
                name = name.substring(0, name.length() - 4);
            } else {
                name = "decrypted-" + name;
            }
            return download(decryptedData, name);

        } catch (IllegalArgumentException e) {
            return error(e.getMessage());
        } catch (GeneralSecurityException e) {
            return error("Decryption failed! Incorrect password or the encrypted file "
                    + "has been modified or corrupted.");
        } finally {
            Arrays.fill(passwordChars, '\0');
        }
    }

    private ResponseEntity<byte[]> download(byte[] data, String filename) {
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment()
                                .filename(filename, StandardCharsets.UTF_8)
                                .build()
                                .toString())
                .body(data);
    }

    private ResponseEntity<byte[]> error(String message) {
        return ResponseEntity.badRequest()
                .contentType(MediaType.TEXT_PLAIN)
                .body(message.getBytes(StandardCharsets.UTF_8));
    }
}
