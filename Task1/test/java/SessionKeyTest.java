import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;

import java.util.Arrays;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

public class SessionKeyTest {
    // Material to create secret key from
    private String keymaterial = "iJFnx0SkyC2BQbTOTzjH0Q==";
    // Corresponding secret key bytes
    private byte[] keybytes = {(byte) 0x88, (byte) 0x91, (byte) 0x67, (byte) 0xc7,
                               (byte) 0x44, (byte) 0xa4, (byte) 0xc8, (byte) 0x2d,
                               (byte) 0x81, (byte) 0x41, (byte) 0xb4, (byte) 0xce,
                               (byte) 0x4f, (byte) 0x38, (byte) 0xc7, (byte) 0xd1};
  
    @Test
    public void testSecretKeyIsAES() throws NoSuchAlgorithmException {
        SessionKey key = new SessionKey(128);
        SecretKey secret = key.getSecretKey();

        assertEquals(secret.getAlgorithm(), "AES");
    }

    @Test
    public void testSameStringGivesSameKey() throws NoSuchAlgorithmException {
        SessionKey key1 = new SessionKey(keymaterial);
        SessionKey key2 = new SessionKey(keymaterial);

        assertEquals(key1.getSecretKey(), key2.getSecretKey());
    }

    @Test
    public void testEncodeKeyEqualsString() throws NoSuchAlgorithmException {
        SessionKey key = new SessionKey(keymaterial);

        assertEquals(keymaterial, key.encodeKey());
    }

    @Test
    public void testGeneratedKeysEqual() throws NoSuchAlgorithmException {
        SessionKey key1 = new SessionKey(128);
        SessionKey key2 = new SessionKey(key1.encodeKey());

        assertEquals(key1.getSecretKey(), key2.getSecretKey());
    }

    @Test
    public void testSecretKeyEqualsSecret() throws NoSuchAlgorithmException {

        SessionKey key = new SessionKey(keymaterial);
        byte[] secretkeybytes = key.getSecretKey().getEncoded();
        assertArrayEquals(secretkeybytes, keybytes);
    }

}
