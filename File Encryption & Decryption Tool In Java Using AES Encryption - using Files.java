import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;

public class AESFileTool {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding"; // Use CBC in production

    public static void encrypt(File inputFile, File outputFile, SecretKey secretKey)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
                   InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        try (FileInputStream inputStream = new FileInputStream(inputFile);
             FileOutputStream outputStream = new FileOutputStream(outputFile);
             CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher)) {

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                cipherOutputStream.write(buffer, 0, bytesRead);
            }
        }
    }

    public static void decrypt(File inputFile, File outputFile, SecretKey secretKey)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
                   InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        try (FileInputStream inputStream = new FileInputStream(inputFile);
             CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher);
             FileOutputStream outputStream = new FileOutputStream(outputFile)) {

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = cipherInputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }
    }

    public static void main(String[] args) {
        try {
            // Generate a key (for demonstration; in real apps, manage securely)
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            keyGen.init(128); // 128-bit key
            SecretKey secretKey = keyGen.generateKey();

            File originalFile = new File("plaintext.txt");
            File encryptedFile = new File("encrypted.aes");
            File decryptedFile = new File("decrypted.txt");

            try (FileWriter writer = new FileWriter(originalFile)) {
                writer.write("This is a secret message.");
            }

            System.out.println("Encrypting file...");
            encrypt(originalFile, encryptedFile, secretKey);
            System.out.println("File encrypted to: " + encryptedFile.getAbsolutePath());

            System.out.println("Decrypting file...");
            decrypt(encryptedFile, decryptedFile, secretKey);
            System.out.println("File decrypted to: " + decryptedFile.getAbsolutePath());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
