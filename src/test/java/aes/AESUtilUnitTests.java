package aes;

import aes.model.Person;
import aes.util.AESUtil;
import org.assertj.core.api.WithAssertions;
import org.junit.Test;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class AESUtilUnitTests implements WithAssertions {

    @Test
    public void shouldSuccessfullyEncryptPlainTextAndDecryptCipherText()
            throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {

        // given
        String input = "plainText";
        SecretKey key = AESUtil.generateSecretKey(128);
        IvParameterSpec ivParameterSpec = AESUtil.generateIv();
        String algorithm = "AES/CBC/PKCS5Padding";

        // when
        String cipherText = AESUtil.encrypt(algorithm, input, key, ivParameterSpec);
        String plainText = AESUtil.decrypt(algorithm, cipherText, key, ivParameterSpec);

        // then
        assertThat(input).isEqualTo(plainText);
    }

    @Test
    public void shouldSuccessfullyEncryptPlainTextAndDecryptCipherTextPasswordBased()
            throws InvalidKeySpecException, NoSuchAlgorithmException,
            IllegalBlockSizeException, InvalidKeyException, BadPaddingException,
            InvalidAlgorithmParameterException, NoSuchPaddingException {

        String plainText = "plainText";
        String password = "passwd";
        String salt = "01234567";
        IvParameterSpec ivParameterSpec = AESUtil.generateIv();
        SecretKey key = AESUtil.generateSecretKeyFromPassword(password,salt);
        String cipherText = AESUtil.encryptPasswordBased(plainText, key, ivParameterSpec);
        String decryptedCipherText = AESUtil.decryptPasswordBased(
                cipherText, key, ivParameterSpec);

        assertThat(plainText).isEqualTo(decryptedCipherText);
    }

    @Test
    public void shouldSuccessfullyEncryptAndDecryptAnObject()
            throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
            InvalidAlgorithmParameterException, NoSuchPaddingException, IOException,
            BadPaddingException, ClassNotFoundException {

        Person person = new Person("First", "Last", 23);

        SecretKey key = AESUtil.generateSecretKey(128);
        IvParameterSpec ivParameterSpec = AESUtil.generateIv();
        String algorithm = "AES/CBC/PKCS5Padding";

        SealedObject sealedObject = AESUtil.encryptObject(
                algorithm, person, key, ivParameterSpec);

        Person decryptedObject = (Person) AESUtil.decryptObject(
                algorithm, sealedObject, key, ivParameterSpec);

        assertThat(person).isEqualTo(decryptedObject);
    }
}
