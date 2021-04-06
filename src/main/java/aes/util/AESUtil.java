package aes.util;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class AESUtil {

    public static String encrypt(String algorithm, String input, SecretKey secretKey, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        byte[] cipherText = cipher.doFinal(input.getBytes());

        return Base64.getEncoder()
                .encodeToString(cipherText);
    }

    public static String decrypt(String algorithm, String cipherText, SecretKey secretKey, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

        byte[] plainText = cipher.doFinal(Base64.getDecoder()
                .decode(cipherText));

        return new String(plainText);
    }

    public static String encryptPasswordBased(String plainText, SecretKey secretKey, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        return Base64.getEncoder()
                .encodeToString(cipher.doFinal(plainText.getBytes()));
    }

    public static String decryptPasswordBased(String cipherText, SecretKey secretKey, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

        return new String(cipher.doFinal(Base64.getDecoder()
                .decode(cipherText)));
    }

    public static SealedObject encryptObject(String algorithm, Serializable object, SecretKey secretKey, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, IOException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        return new SealedObject(object, cipher);
    }

    public static Serializable decryptObject(String algorithm, SealedObject sealedObject, SecretKey secretKey, IvParameterSpec iv)
            throws ClassNotFoundException, BadPaddingException, IllegalBlockSizeException, IOException, InvalidAlgorithmParameterException,
            InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

        return (Serializable) sealedObject.getObject(cipher);
    }

    //first approach, generate secret key derived from SecureRandom
    public static SecretKey generateSecretKey(int n) throws NoSuchAlgorithmException {

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);

        return keyGenerator.generateKey();
    }

    //second approach, generate secret key derived from password with additional has input(salt)
    public static SecretKey generateSecretKeyFromPassword(String password, String salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);

        return new SecretKeySpec(secretKeyFactory.generateSecret(keySpec)
                .getEncoded(), "AES");
    }

    public static IvParameterSpec generateIv() {

        //create an empty byte array
        byte[] iv = new byte[16];

        //fill the array with secure random bytes
        new SecureRandom().nextBytes(iv);

        return new IvParameterSpec(iv);
    }
}
