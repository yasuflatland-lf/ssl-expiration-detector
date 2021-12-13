package ssl.expiration.detector;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;

@Slf4j
@NoArgsConstructor
public class Validator {
    public boolean exec(String fqdn) {
        HttpsURLConnection conn = null;
        boolean ret = false;

        try {
            // configure the SSLContext with a TrustManager
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(new KeyManager[0], new TrustManager[]{new DefaultTrustManager()}, new SecureRandom());
            SSLContext.setDefault(ctx);

            URL url = new URL(fqdn);
            conn = (HttpsURLConnection) url.openConnection();
            conn.setHostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String arg0, SSLSession arg1) {
                    return true;
                }
            });

            if(HttpsURLConnection.HTTP_OK == conn.getResponseCode()) {
                Certificate[] certs = conn.getServerCertificates();
                for (Certificate cert : certs) {
                    X509Certificate x509 = (X509Certificate)cert;
                    System.out.println("fqdn : " + fqdn + "<" + x509.getNotAfter().toString() + ">");

                    if(cert instanceof X509Certificate) {
                        try {
                            ( (X509Certificate) cert).checkValidity();
                            System.out.println("Certificate is active for current date");
                        } catch(CertificateExpiredException cee) {
                            System.out.println("Certificate is expired");
                        }
                    }
                }
                ret = true;
            }

        } catch (Throwable e) {
            if (e instanceof NoSuchAlgorithmException) {
                log.error("NoSuchAlgorithmException : " + e.getMessage());
            } else if (e instanceof IOException) {
                log.error("IOException : " + e.getMessage());
            } else if (e instanceof KeyManagementException) {
                log.error("KeyManagementException : " + e.getMessage());
            } else {
                log.error("Other exception : " + e.getMessage());
            }
        } finally {
            if (null != conn) {
                conn.disconnect();
            }
        }

        return ret;
    }

    private static class DefaultTrustManager implements X509TrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }
    }
}
