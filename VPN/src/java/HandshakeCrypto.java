import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class HandshakeCrypto {
    private static CertificateFactory certFactory;
    private static FileInputStream certFile;
    private static X509Certificate certificate;


    public static byte[] encrypt(byte[] plaintext, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher;
        // Initialize it to null at first because it is empty.
        byte[] cipherText = null;
        cipher = Cipher.getInstance("RSA");
        //MODE IS IMPORTANT
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipherText = cipher.doFinal(plaintext);

        //Return cipher text as byte array
        return cipherText;
    }

    public static byte[] decrypt(byte[] ciphertext, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher;
        byte[] plainText = null;
        cipher = Cipher.getInstance("RSA");
        //MODE IS IMPORTANT
        cipher.init(Cipher.DECRYPT_MODE, key);
        plainText = cipher.doFinal(ciphertext);

        //Return plain text as byte array
        return plainText;
    }

    // Extracts a public key from a certificate file.
    public static PublicKey getPublicKeyFromCertFile(String certfile) throws CertificateException, FileNotFoundException {
        certFactory = CertificateFactory.getInstance("X.509");
        certFile = new FileInputStream(certfile);
        certificate = (X509Certificate) certFactory.generateCertificate(certFile);

        return certificate.getPublicKey();
    }

    //  Extracts a private key from a key file
    public static PrivateKey getPrivateKeyFromKeyFile(String keyfile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Path path = Paths.get(keyfile);
        byte[] privKeyBytes = Files.readAllBytes(path);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }
}
