import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SessionDecrypter {

    private byte[] IV;
    private Cipher cipher;
    private SessionKey sessionKey;

    public SessionDecrypter(String encodeKey, String encodeIV) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        sessionKey = new SessionKey(encodeKey);
        IV = Base64.getDecoder().decode(encodeIV);
        cipher = Cipher.getInstance("AES/CTR/NoPadding" );
        cipher.init(Cipher.DECRYPT_MODE, sessionKey.getSecretKey(), new IvParameterSpec(IV));
    }

    public SessionDecrypter(byte[] key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        sessionKey = new SessionKey(key);
        IV = iv;
        cipher = Cipher.getInstance("AES/CTR/NoPadding" );
        cipher.init(Cipher.DECRYPT_MODE, sessionKey.getSecretKey(), new IvParameterSpec(IV));
    }


    public CipherInputStream openCipherInputStream(InputStream inputStream) {
        return new CipherInputStream(inputStream, cipher);
    }

}