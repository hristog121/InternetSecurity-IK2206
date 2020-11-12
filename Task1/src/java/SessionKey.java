/**
 *
 */

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;


public class SessionKey {
    private SecretKey secretKey;

    public SessionKey(Integer keylength) throws NoSuchAlgorithmException {

        // KeyGenerator object
        KeyGenerator KeyGen = KeyGenerator.getInstance("AES");

        //create a secure random object
        SecureRandom secRandom = new SecureRandom();

        // KeyGen init
        KeyGen.init(keylength, secRandom);

        // Make a key and store it in secret key
        this.secretKey = KeyGen.generateKey();
    }

    public SessionKey(String encodedKey){
        // Decode the Base64 Encoded String
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        this.secretKey = new SecretKeySpec(decodedKey,0,decodedKey.length, "AES");
    }

    public SessionKey(byte[] Key) {
        this.secretKey = new SecretKeySpec(Key,"AES");
    }

    public SecretKey getSecretKey() {
        return this.secretKey;
    }

    public String encodeKey() {
        return Base64.getEncoder().encodeToString(this.secretKey.getEncoded());
    }

}