import kz.vault.AesFileEncryptor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("AES-256-GCM Файл Шифрлағыш Тестілері")
class AesFileEncryptorTest {

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("1. Кілт ұзындығы (256 бит) мен AES алгоритмін тексеру")
    void testDeriveKeyLengthAndAlgorithm() throws Exception {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        SecretKey key = AesFileEncryptor.deriveKey("StrongPass123!".toCharArray(), salt);

        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals(32, key.getEncoded().length);
    }

    @Test
    @DisplayName("2. Бірдей құпиясөз бен salt бірдей кілт беретінін тексеру")
    void testSamePasswordAndSaltProduceSameKey() throws Exception {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        SecretKey key1 = AesFileEncryptor.deriveKey("MySecret".toCharArray(), salt);
        SecretKey key2 = AesFileEncryptor.deriveKey("MySecret".toCharArray(), salt);

        assertArrayEquals(key1.getEncoded(), key2.getEncoded());
    }

    @Test
    @DisplayName("3. Әртүрлі salt мәндері бөлек кілттер жасайтынын тексеру")
    void testDifferentSaltsProduceDifferentKeys() throws Exception {
        byte[] salt1 = new byte[16];
        byte[] salt2 = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt1);
        random.nextBytes(salt2);

        SecretKey key1 = AesFileEncryptor.deriveKey("SamePassword".toCharArray(), salt1);
        SecretKey key2 = AesFileEncryptor.deriveKey("SamePassword".toCharArray(), salt2);

        assertFalse(Arrays.equals(key1.getEncoded(), key2.getEncoded()));
    }

    @Test
    @DisplayName("4. Мәтіндік файлды сәтті шифрлау және дешифрлау")
    void testEncryptAndDecryptTextFile() throws Exception {
        Path original = tempDir.resolve("plain.txt");
        Path encrypted = tempDir.resolve("plain.enc");
        Path decrypted = tempDir.resolve("decrypted.txt");

        String content = "Confidential project report by Arslan Rozmetov.";
        Files.writeString(original, content);
        char[] password = "CorrectPassword2026".toCharArray();

        AesFileEncryptor.encryptFile(original, encrypted, password);
        AesFileEncryptor.decryptFile(encrypted, decrypted, password);

        assertEquals(content, Files.readString(decrypted));
    }

    @Test
    @DisplayName("5. Шифрланған файл бастапқы мәтіннен өзгеше болуын тексеру")
    void testEncryptedFileDiffersFromOriginal() throws Exception {
        Path original = tempDir.resolve("data.txt");
        Path encrypted = tempDir.resolve("data.enc");

        byte[] originalBytes = "Secret message inside file".getBytes(StandardCharsets.UTF_8);
        Files.write(original, originalBytes);

        AesFileEncryptor.encryptFile(original, encrypted, "Pass123".toCharArray());
        byte[] encryptedBytes = Files.readAllBytes(encrypted);

        assertFalse(Arrays.equals(originalBytes, encryptedBytes));
        assertTrue(encryptedBytes.length > originalBytes.length);
    }

    @Test
    @DisplayName("6. Қате құпиясөз енгізгенде дешифрлаудан бас тарту")
    void testWrongPasswordThrowsAuthenticationException() throws Exception {
        Path original = tempDir.resolve("secret.txt");
        Path encrypted = tempDir.resolve("secret.enc");
        Path decrypted = tempDir.resolve("out.txt");

        Files.writeString(original, "Top secret data");
        AesFileEncryptor.encryptFile(original, encrypted, "RightPassword".toCharArray());

        assertThrows(Exception.class, () ->
                AesFileEncryptor.decryptFile(encrypted, decrypted, "WrongPassword".toCharArray())
        );
    }

    @Test
    @DisplayName("7. Шифрланған файл бүлінсе (өзгертілсе) қате шығару")
    void testTamperedCiphertextFailsDecryption() throws Exception {
        Path original = tempDir.resolve("integrity.txt");
        Path encrypted = tempDir.resolve("integrity.enc");
        Path decrypted = tempDir.resolve("out.txt");

        Files.writeString(original, "Original uncorrupted message");
        char[] password = "Password123".toCharArray();
        AesFileEncryptor.encryptFile(original, encrypted, password);

        byte[] fileBytes = Files.readAllBytes(encrypted);
        fileBytes[fileBytes.length - 1] ^= 0xFF;
        Files.write(encrypted, fileBytes);

        assertThrows(Exception.class, () ->
                AesFileEncryptor.decryptFile(encrypted, decrypted, password)
        );
    }

    @Test
    @DisplayName("8. Үлкен файлды (2 МБ) бөліп шифрлау және қалпына келтіру")
    void testLargeFileChunkedEncryptionAndDecryption() throws Exception {
        Path largeOriginal = tempDir.resolve("large.bin");
        Path largeEncrypted = tempDir.resolve("large.enc");
        Path largeDecrypted = tempDir.resolve("large_out.bin");

        byte[] largeData = new byte[2 * 1024 * 1024];
        new SecureRandom().nextBytes(largeData);
        Files.write(largeOriginal, largeData);

        char[] password = "LargeFilePass!".toCharArray();
        AesFileEncryptor.encryptFile(largeOriginal, largeEncrypted, password);
        AesFileEncryptor.decryptFile(largeEncrypted, largeDecrypted, password);

        assertArrayEquals(largeData, Files.readAllBytes(largeDecrypted));
    }

    @Test
    @DisplayName("9. Бос файлды шифрлау және дешифрлау")
    void testEmptyFileEncryptionAndDecryption() throws Exception {
        Path emptyOriginal = tempDir.resolve("empty.txt");
        Path emptyEncrypted = tempDir.resolve("empty.enc");
        Path emptyDecrypted = tempDir.resolve("empty_out.txt");

        Files.write(emptyOriginal, new byte[0]);
        char[] password = "EmptyFilePass".toCharArray();

        AesFileEncryptor.encryptFile(emptyOriginal, emptyEncrypted, password);
        AesFileEncryptor.decryptFile(emptyEncrypted, emptyDecrypted, password);

        assertEquals(0, Files.readAllBytes(emptyDecrypted).length);
    }

    @Test
    @DisplayName("10. Тақырыбы (salt/IV) бүлінген файлды оқығанда қате беру")
    void testCorruptedHeaderThrowsException() throws Exception {
        Path shortFile = tempDir.resolve("corrupted.enc");
        Path output = tempDir.resolve("out.txt");
        Files.write(shortFile, new byte[10]);

        assertThrows(IllegalArgumentException.class, () ->
                AesFileEncryptor.decryptFile(shortFile, output, "Pass".toCharArray())
        );
    }
}
