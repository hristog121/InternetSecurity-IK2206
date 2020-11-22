import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class SessionKey {

    private SecretKey secretKey;

    // Source from http://tutorials.jenkov.com/java-cryptography/index.html
    SessionKey(Integer keylength) throws NoSuchAlgorithmException {

        //Creating a KeyGenerator object
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");

        //Creating a SecureRandom object
        SecureRandom secureRandom = new SecureRandom();

        //Initializing the KeyGenerator
        keyGen.init(keylength, secureRandom);

        //Creating/Generating a key
        this.secretKey = keyGen.generateKey();
    }


    SessionKey(byte[] keybytes) {
        // Decode the base64 Encoded string
        //byte[] decodedKey = Base64.getDecoder().decode(encodedkey);

        // Rebuild key using SecretKeySpec
        this.secretKey = new SecretKeySpec(keybytes, 0, keybytes.length, "AES");
    }


    public SecretKey getSecretKey() {
        return this.secretKey;
    }


    public byte[] getKeyBytes() {
        return secretKey.getEncoded();
    }
}