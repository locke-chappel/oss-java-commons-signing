package io.github.lc.oss.commons.signing;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import io.github.lc.oss.commons.util.IoTools;

public class Util {
    public static KeyPair loadKeyPair(String keyStorePath, String alias, char[] password) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream(IoTools.getAbsoluteFilePath(keyStorePath)), password);
            PrivateKey pk = (PrivateKey) ks.getKey(alias, password);
            Certificate cert = ks.getCertificate(alias);
            return new KeyPair(cert.getPublicKey(), pk);
        } catch (Exception ex) {
            throw new RuntimeException("Error loading KeyPair", ex);
        }
    }

    public static PublicKey loadPublicKey(String certPath) {
        try (InputStream is = new FileInputStream(IoTools.getAbsoluteFilePath(certPath))) {
            CertificateFactory fac = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) fac.generateCertificate(is);
            return certificate.getPublicKey();
        } catch (Exception ex) {
            throw new RuntimeException("Error loading public key", ex);
        }
    }

    public static PublicKey loadPublicKeyFromResource(String resourcePath) {
        try (InputStream is = Util.class.getClassLoader().getResourceAsStream(resourcePath)) {
            CertificateFactory fac = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) fac.generateCertificate(is);
            return certificate.getPublicKey();
        } catch (Exception ex) {
            throw new RuntimeException("Error loading public key", ex);
        }
    }

    public static PublicKey loadPublicKeyFromData(String cert) {
        try (InputStream is = new ByteArrayInputStream(cert.getBytes(StandardCharsets.UTF_8))) {
            CertificateFactory fac = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) fac.generateCertificate(is);
            return certificate.getPublicKey();
        } catch (Exception ex) {
            throw new RuntimeException("Error loading public key", ex);
        }
    }

    public static PrivateKey loadPrivateKeyFromData(String key, String keyType) {
        try {
            String data = key;
            data = data.replace("-----BEGIN PRIVATE KEY-----", "");
            data = data.replace("-----END PRIVATE KEY-----", "");
            data = data.replaceAll("\\s+", "");
            byte[] bytes = Base64.getDecoder().decode(data);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance(keyType);
            return kf.generatePrivate(keySpec);
        } catch (Exception ex) {
            throw new RuntimeException("Error loading private key", ex);
        }
    }

    private Util() {
    }
}
