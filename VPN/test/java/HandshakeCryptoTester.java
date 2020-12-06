import java.security.*;

class HandshakeTester {
    static String PRIVATEKEYFILE = "/Users/iceroot/WorkingDev/InternetSecurity-IK2206/VPN/src/java/CA.der";
    static String CERTFILE = "/Users/iceroot/WorkingDev/InternetSecurity-IK2206/VPN/src/java/ca.pem";
    static String PLAINTEXT = "Time flies like an arrow. Fruit flies like a banana.";
    static String ENCODING = "UTF-8"; /* For converting between strings and byte arrays */
    
    static public void main(String[] args) throws Exception {

        /* Extract key pair */
        PublicKey publickey = HandshakeCrypto.getPublicKeyFromCertFile(CERTFILE);
        PrivateKey privatekey = HandshakeCrypto.getPrivateKeyFromKeyFile(PRIVATEKEYFILE);
        System.out.println(privatekey);
        
        /* Encode string as bytes */
        byte[] plaininputbytes = PLAINTEXT.getBytes(ENCODING);
        /* Encrypt it */
        byte[] cipher = HandshakeCrypto.encrypt(plaininputbytes, publickey);
        /* Then decrypt back */
        byte[] plainoutputbytes = HandshakeCrypto.decrypt(cipher, privatekey);
        /* Decode bytes into string */
        String plainoutput = new String(plainoutputbytes, ENCODING);
        if (plainoutput.equals(PLAINTEXT)) {
            System.out.println("Pass. Input and output strings are the same: \"" + PLAINTEXT + "\"");
        }
        else {
            System.out.println("Fail. Expected \"" + PLAINTEXT + "\", but got \"" + plainoutput + "\'");
        }
    }
}
