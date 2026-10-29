package com.ruchitha.encryption.service;
// spring import
import org.springframework.stereotype.Service;
// cryptographic imports
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEKeySpec;
// java utility imports
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

@Service
public class FileEncryptionService {

    private static final String AES = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String KDF = "PBKDF2WithHmacSHA256";

    private static final int SALT_LENGTH = 16;
    private static final int NONCE_LENGTH = 12;
    private static final int KEY_LENGTH = 256;
    private static final int TAG_LENGTH_BITS = 128;
    private static final int ITERATIONS = 600_000;

    private static final byte[] MAGIC = "RUCHITAAES1".getBytes(StandardCharsets.US_ASCII);

    private final SecureRandom secureRandom = new SecureRandom();

    public byte[] encrypt(byte[] fileData, char[] password)
            throws GeneralSecurityException {

        validatePassword(password);

        byte[] salt = new byte[SALT_LENGTH];
        byte[] nonce = new byte[NONCE_LENGTH];

        secureRandom.nextBytes(salt);
        secureRandom.nextBytes(nonce);

        SecretKey key = deriveKey(password,salt);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);

        cipher.init(
                Cipher.ENCRYPT_MODE,
                key,
                new GCMParameterSpec(TAG_LENGTH_BITS,nonce)
        );

        byte[] ciphertext = cipher.doFinal(fileData);

        ByteBuffer output = ByteBuffer.allocate(
                MAGIC.length+SALT_LENGTH+NONCE_LENGTH+ciphertext.length
        );

        output.put(MAGIC);
        output.put(salt);
        output.put(nonce);
        output.put(ciphertext);

        Arrays.fill(salt, (byte) 0);
        Arrays.fill(nonce, (byte) 0);

        return output.array();
    }

    public byte[] decrypt (byte[] encryptedData, char[] password)
        throws GeneralSecurityException{
         validatePassword(password);

         int headerLength = MAGIC.length + SALT_LENGTH + NONCE_LENGTH;

         if (encryptedData == null || encryptedData.length < headerLength + 16)
         {
             throw new GeneralSecurityException("Invalid or incomplete encrypted file");
         }

         ByteBuffer input = ByteBuffer.wrap(encryptedData);

         byte[] magic = new byte[MAGIC.length];
         input.get(magic);

         if (! Arrays.equals(magic,MAGIC))
         {
             throw new GeneralSecurityException("This is not a supported encrypted file");
         }

         byte[] salt = new byte[SALT_LENGTH];
         byte[] nonce = new byte[NONCE_LENGTH];
         input.get(salt);
         input.get(nonce);

         byte[] ciphertext = new byte[input.remaining()];
         input.get(ciphertext);

         try {
                 SecretKey key = deriveKey(password, salt);

                 Cipher cipher = Cipher.getInstance(TRANSFORMATION);

                 cipher.init(
                     Cipher.DECRYPT_MODE,
                     key,
                     new GCMParameterSpec(TAG_LENGTH_BITS, nonce)
                 );
                 return cipher.doFinal(ciphertext);
             }

         catch (AEADBadTagException e)
             {
                 throw new GeneralSecurityException("Incorrect password or encrypted file has been modified");
             }

         finally {
             Arrays.fill(salt, (byte)0);
             Arrays.fill(nonce, (byte)0);
             Arrays.fill(ciphertext, (byte) 0);
         }
    }
    private SecretKey deriveKey( char[] password,byte[] salt)
        throws GeneralSecurityException{
        PBEKeySpec spec = new PBEKeySpec(
                password,
                salt,
                ITERATIONS,
                KEY_LENGTH
        );

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF);
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();

            try {
                return new SecretKeySpec(keyBytes,AES);
            }
            finally {
                Arrays.fill(keyBytes, (byte)0);
            }
        }finally {
            spec.clearPassword();
        }
 
    }
    private void validatePassword(char[] password) {
        if (password == null || password.length < 12) {
            throw new IllegalArgumentException("Password must contain at least 12 characters.");
        }

        boolean upper = false, lower = false, digit = false, special = false;

        for (char c : password) {
            if (Character.isUpperCase(c)) upper = true;
            else if (Character.isLowerCase(c)) lower = true;
            else if (Character.isDigit(c)) digit = true;
            else special = true;
        }

        if (!upper)   throw new IllegalArgumentException("Password must contain an uppercase letter.");
        if (!lower)   throw new IllegalArgumentException("Password must contain a lowercase letter.");
        if (!digit)   throw new IllegalArgumentException("Password must contain a number.");
        if (!special) throw new IllegalArgumentException("Password must contain at least one special character.");
    }
}
