import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SessionEncrypter {
    private SessionKey sessionKey;
    Cipher cipher;
    byte [] counter;
    IvParameterSpec ivParameterSpec;
    SessionEncrypter(Integer keyLenght) throws NoSuchAlgorithmException {
        sessionKey = new SessionKey(keyLenght);
        SecureRandom random = new SecureRandom();
        counter = random.generateSeed(16);
        ivParameterSpec = new IvParameterSpec(counter);
    }

    SessionEncrypter(byte[] key, byte[] iv){
        sessionKey = new SessionKey(key);
        ivParameterSpec  = new IvParameterSpec(iv);

    }


    byte[] getKeyBytes(){
        return sessionKey.getSecretKey().getEncoded();
    }

    byte[] getIVBytes(){
        return ivParameterSpec.getIV();
    }

    CipherOutputStream openCipherOutputStream(OutputStream output) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException {
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey.getSecretKey(), ivParameterSpec);
        return new CipherOutputStream(output, cipher);
    }
}