import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.*;
import java.util.Base64;

public class VerifyCertificate {
    private static CertificateFactory certFactory;
    private static X509Certificate caCertificate;
    private static X509Certificate userCertificate;
    //get certs
    public static X509Certificate getCert(String certificate) throws IOException, CertificateException {
        InputStream certInputStream = null;
        X509Certificate cert;
        try {
            certInputStream = new FileInputStream(certificate);
            certFactory = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) certFactory.generateCertificate(certInputStream);
        } finally {
            if (certInputStream != null ) {
                certInputStream.close();
            }
        }
        return cert;
    }

    public static void getVerifyCaUser(String caCert, String userCert) throws Exception {
        X509Certificate caCertificate = null;
        X509Certificate userCertificate = null;
        try {
            //System.out.println("HERE: VERIFY CERT");
            caCertificate = getCert(caCert);
            userCertificate = decodeCert(userCert);
            //userCertificate = getCert(userCert);

            caCertificate.verify(caCertificate.getPublicKey());
            userCertificate.verify(caCertificate.getPublicKey());
            System.out.println("Pass VERIFICATION");
        }
        catch(Exception E){
            System.out.println("Fail VERIFICATION");
            E.printStackTrace();
            //throw new Exception(E);
        }

    }


    public static X509Certificate decodeCert(String certString) throws CertificateException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        byte [] certByte = Base64.getDecoder().decode(certString);
        InputStream inputStream = new ByteArrayInputStream(certByte);
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(inputStream);
        return cert;
    }

    public static X509Certificate createCertificate(String stringCertificate) throws CertificateException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        byte[] bytes = Base64.getDecoder().decode(stringCertificate);
        InputStream in = new ByteArrayInputStream(bytes);
        return (X509Certificate) certFactory.generateCertificate(in);
    }

    public static String encodeCertificate(X509Certificate cert) throws CertificateEncodingException {
        return Base64.getEncoder().encodeToString(cert.getEncoded());
    }




    /**
     * Main method to test the methods above
     * The method takes 2 arguments from the terminal - the CA.pem and the user.pem
     * @param args
     * @throws Exception
     */
/*    public static void main(String[] args) throws Exception {

        String CA = args[0];
        String user = args[1];
        String caCertOut = getCert(CA).getSubjectDN().getName();
        String userCertOut = getCert(user).getSubjectDN().getName();
        System.out.println(caCertOut);
        System.out.println(userCertOut);

        // Checks and prints pass and fail for the certs
        getVerifyCaUser(getCert(CA), getCert(user));
    }*/

}