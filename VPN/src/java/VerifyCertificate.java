import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.*;

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

    public static void getVerifyCaUser(X509Certificate caCert, X509Certificate userCert) throws Exception {
        try {
            caCert.checkValidity();
            userCert.checkValidity();
            caCert.verify(caCert.getPublicKey());
            userCert.verify(caCert.getPublicKey());
            System.out.println("Pass");
        }
        catch(Exception E){
            System.out.println("Fail");
            System.out.println(E.toString());
            throw new Exception();
        }

    }

    /**
     * Main method to test the methods above
     * The method takes 2 arguments from the terminal - the CA.pem and the user.pem
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {

        String CA = args[0];
        String user = args[1];
        String caCertOut = getCert(CA).getSubjectDN().getName();
        String userCertOut = getCert(user).getSubjectDN().getName();
        System.out.println(caCertOut);
        System.out.println(userCertOut);

        // Checks and prints pass and fail for the certs
        getVerifyCaUser(getCert(CA), getCert(user));
    }

}