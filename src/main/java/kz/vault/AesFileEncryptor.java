package kz.vault;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Scanner;

public class AesFileEncryptor {

    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int SALT_LENGTH = 16;       // 128 бит
    private static final int IV_LENGTH = 12;         // 96 бит (GCM стандарты)
    private static final int TAG_LENGTH_BITS = 128;  // 128 бит аутентификация тегі
    private static final int KEY_LENGTH_BITS = 256;  // AES-256
    private static final int ITERATIONS = 65536;     // PBKDF2 итерация саны
    private static final int BUFFER_SIZE = 8192;     // 8 КБ буфер

    // 1. Құпиясөз бен salt арқылы PBKDF2 көмегімен AES-256 кілтін алу
    public static SecretKey deriveKey(char[] password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGORITHM);
        KeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH_BITS);
        byte[] secretBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(secretBytes, "AES");
    }

    // 2. Файлды шифрлау
    public static void encryptFile(Path inputPath, Path outputPath, char[] password) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);

        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);

        SecretKey key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

        try (InputStream in = Files.newInputStream(inputPath);
             OutputStream out = Files.newOutputStream(outputPath)) {

            out.write(salt);
            out.write(iv);

            try (CipherOutputStream cipherOut = new CipherOutputStream(out, cipher)) {
                byte[] buffer = new byte[BUFFER_SIZE];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    cipherOut.write(buffer, 0, bytesRead);
                }
            }
        }
    }

    // 3. Файлды дешифрлау
    public static void decryptFile(Path inputPath, Path outputPath, char[] password) throws Exception {
        try (InputStream in = Files.newInputStream(inputPath)) {
            byte[] salt = in.readNBytes(SALT_LENGTH);
            if (salt.length < SALT_LENGTH) {
                throw new IllegalArgumentException("Шифрланған файл бүлінген: salt табылмады.");
            }

            byte[] iv = in.readNBytes(IV_LENGTH);
            if (iv.length < IV_LENGTH) {
                throw new IllegalArgumentException("Шифрланған файл бүлінген: IV табылмады.");
            }

            SecretKey key = deriveKey(password, salt);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

            try (CipherInputStream cipherIn = new CipherInputStream(in, cipher);
                 OutputStream out = Files.newOutputStream(outputPath)) {

                byte[] buffer = new byte[BUFFER_SIZE];
                int bytesRead;
                while ((bytesRead = cipherIn.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }
        }
    }

    public static void main(String[] args) {
        Path originalFile = Path.of("secret_data.txt");
        Path encryptedFile = Path.of("secret_data.txt.enc");
        Path decryptedFile = Path.of("secret_data_decrypted.txt");

        try (Scanner scanner = new Scanner(System.in)) {
            System.out.println("==========================================");
            System.out.println("     AES-256-GCM ФАЙЛ ШИФРЛАҒЫШЫ (JCA)    ");
            System.out.println("==========================================");
            System.out.println("Орындаған: Розметов Арслан");

            while (true) {
                System.out.println("\nӘрекетті таңдаңыз:");
                System.out.println("1. Мәтінді жазып шифрлау");
                System.out.println("2. Шифрланған файлды дешифрлау (қалпына келтіру)");
                System.out.println("0. Шығу");
                System.out.print("Таңдауыңыз: ");
                String choice = scanner.nextLine();

                if (choice.equals("1")) {
                    System.out.print("Шифрланатын мәтінді енгізіңіз: ");
                    String text = scanner.nextLine();
                    if (text.isBlank()) {
                        text = "Құпия ақпарат. Орындаған: Розметов Арслан.";
                    }
                    Files.writeString(originalFile, text);

                    System.out.print("Шифрлау паролін орнатыңыз: ");
                    char[] password = scanner.nextLine().toCharArray();

                    encryptFile(originalFile, encryptedFile, password);
                    Arrays.fill(password, '\0');

                    System.out.println("Файл сәтті шифрланды -> " + encryptedFile);

                } else if (choice.equals("2")) {
                    if (!Files.exists(encryptedFile)) {
                        System.out.println("Алдымен 1-тармақты таңдап файлды шифрлаңыз!");
                        continue;
                    }

                    System.out.print("Қалпына келтіру үшін пароліңізді енгізіңіз: ");
                    char[] password = scanner.nextLine().toCharArray();

                    try {
                        decryptFile(encryptedFile, decryptedFile, password);
                        System.out.println("Құпиясөз дұрыс! Файл қалпына келтірілді -> " + decryptedFile);
                        System.out.println("Файл ішіндегі мәтін: " + Files.readString(decryptedFile));
                    } catch (Exception e) {
                        System.out.println("ҚАТЕ: Пароль дұрыс емес немесе файл бүлінген! Дешифрлау мүмкін емес.");
                    } finally {
                        Arrays.fill(password, '\0');
                    }

                } else if (choice.equals("0")) {
                    System.out.println("Бағдарлама аяқталды.");
                    break;
                } else {
                    System.out.println("Қате таңдау! Тек 1, 2 немесе 0 санын енгізіңіз.");
                }
            }
        } catch (Exception e) {
            System.err.println("Жүйелік қате: " + e.getMessage());
        }
    }
}
