package com.example.fiu_module.service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

// import org.slf4j.Logger;
// import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

// import com.example.fiu_module.Config.KafkaProducer;

import java.security.MessageDigest;
import java.security.spec.KeySpec;
import java.util.Base64;

@Service
public class Encryptdecrypt {

    // private static final Logger logger =
    // LoggerFactory.getLogger(Encryptdecrypt.class);

    @Value("${webSecretKey}") 
    private String webSecretKey;

    private String decodedWebSecretKey;


    // final String ALGORITHM = "AES";
    // final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    // final int IV_SIZE = 16;

    private static final String AES_ALGO = "AES";
    private static final String KEY_ALGO = "PBKDF2WithHmacSHA256";
    private static final String AES_CBC_PKCS5 = "AES/CBC/PKCS5Padding";
    private static final String CHARSET = "UTF-8";
    private static final int KEY_SIZE = 256;
    private static final int ITERATION_COUNT = 65536;

    // @Autowired
    // private KafkaProducer kafkaProducer;

    private String errorTopic = "aa_redirection_error";
    private String responseTopic = "aa_redirection_response";

     public String encryption(String strToEncrypt, String salt) {
        try {
            IvParameterSpec iv = new IvParameterSpec(new byte[16]); // Zero IV for simplicity
            SecretKeySpec secretKeySpec = generateSecretKey(salt);

            Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);
            byte[] encrypted = cipher.doFinal(strToEncrypt.getBytes(CHARSET));
            return Base64.getUrlEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public String decryption(String strToDecrypt, String salt) {
        try {
            IvParameterSpec iv = new IvParameterSpec(new byte[16]); // Zero IV for simplicity
            SecretKeySpec secretKeySpec = generateSecretKey(salt);

            Cipher cipher = Cipher.getInstance(AES_CBC_PKCS5);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
            byte[] decryptedBytes = cipher.doFinal(Base64.getUrlDecoder().decode(strToDecrypt));
            return new String(decryptedBytes, CHARSET);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private SecretKeySpec generateSecretKey(String salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_ALGO);
        // System.out.println("webSecretkey"+webSecretKey);
        byte[] decodedBytes = Base64.getDecoder().decode(webSecretKey);
        decodedWebSecretKey = new String(decodedBytes);
        // System.out.println("webSecretkey"+decodedWebSecretKey);
        KeySpec spec = new PBEKeySpec(decodedWebSecretKey.toCharArray(), salt.getBytes(CHARSET), ITERATION_COUNT, KEY_SIZE);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), AES_ALGO);
    }

    public String xorEncrypt(String input, String webSecretKey) {
        byte[] inputBytes = input.getBytes();  
        byte[] keyBytes = webSecretKey.getBytes();      
        byte[] outputBytes = new byte[inputBytes.length];
    
        for (int i = 0; i < inputBytes.length; i++) {
            outputBytes[i] = (byte) (inputBytes[i] ^ keyBytes[i % keyBytes.length]);
        }
    
        return Base64.getEncoder().encodeToString(outputBytes);
    }

    public String xorDecrypt(String input, String webSecretKey) {
        byte[] inputBytes = Base64.getDecoder().decode(input);  
        byte[] keyBytes = webSecretKey.getBytes();
        byte[] outputBytes = new byte[inputBytes.length];
    
        for (int i = 0; i < inputBytes.length; i++) {
            outputBytes[i] = (byte) (inputBytes[i] ^ keyBytes[i % keyBytes.length]);  
        }
    
        return new String(outputBytes);  
    }
}




