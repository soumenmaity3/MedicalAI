package com.soumen.MedicalAI.config;

import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

@Component
public class FileEncryptionUtil {

    private static final String ALGO = "AES";
    private static final byte[] KEY = "MySuperSecretKey".getBytes(); // 16 bytes

    public byte[] encrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGO);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }

    public byte[] decrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGO);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, ALGO);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }
}
