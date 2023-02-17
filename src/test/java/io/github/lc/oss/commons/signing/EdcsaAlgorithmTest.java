package io.github.lc.oss.commons.signing;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import io.github.lc.oss.commons.testing.AbstractTest;

public class EdcsaAlgorithmTest extends AbstractTest {
    @Test
    public void test_signAndVerify_strings() {
        EcdsaAlgorithm alg = (EcdsaAlgorithm) Algorithms.ES256;
        Assertions.assertEquals(256, alg.getMinBitLength());

        String privateKey = java.util.Base64.getEncoder().encodeToString(this.getPrivateKey("junit-ecdsa-p256"));
        String publicKey = java.util.Base64.getEncoder().encodeToString(this.getPublicKey("junit-ecdsa-p256"));

        String data = "test data";

        String sig = alg.getSignature(privateKey, data);
        Assertions.assertNotNull(sig);

        boolean result = alg.isSignatureValid(publicKey, data, sig);
        Assertions.assertTrue(result);
    }

    @Test
    public void test_signAndVerify_p256() {
        EcdsaAlgorithm alg = (EcdsaAlgorithm) Algorithms.ES256;
        Assertions.assertEquals(256, alg.getMinBitLength());

        byte[] privateKey = this.getPrivateKey("junit-ecdsa-p256");
        byte[] publicKey = this.getPublicKey("junit-ecdsa-p256");

        byte[] data = new byte[] { 0x00, 0x01, 0x02 };

        String sig = alg.getSignature(privateKey, data);
        Assertions.assertNotNull(sig);

        boolean result = alg.isSignatureValid(publicKey, data, sig);
        Assertions.assertTrue(result);
    }

    @Test
    public void test_signAndVerify_sec() {
        EcdsaAlgorithm alg = (EcdsaAlgorithm) Algorithms.ES256K;
        Assertions.assertEquals(256, alg.getMinBitLength());

        byte[] privateKey = this.getPrivateKey("junit-ecdsa-p256");
        byte[] publicKey = this.getPublicKey("junit-ecdsa-p256");

        byte[] data = new byte[] { 0x00, 0x01, 0x02 };

        String sig = alg.getSignature(privateKey, data);
        Assertions.assertNotNull(sig);

        boolean result = alg.isSignatureValid(publicKey, data, sig);
        Assertions.assertTrue(result);
    }

    @Test
    public void test_signAndVerify_p384() {
        EcdsaAlgorithm alg = (EcdsaAlgorithm) Algorithms.ES384;
        Assertions.assertEquals(384, alg.getMinBitLength());

        byte[] privateKey = this.getPrivateKey("junit-ecdsa-p384");
        byte[] publicKey = this.getPublicKey("junit-ecdsa-p384");

        byte[] data = new byte[] { 0x00, 0x01, 0x02 };

        String sig = alg.getSignature(privateKey, data);
        Assertions.assertNotNull(sig);

        boolean result = alg.isSignatureValid(publicKey, data, sig);
        Assertions.assertTrue(result);
    }

    @Test
    public void test_signAndVerify_p521() {
        EcdsaAlgorithm alg = (EcdsaAlgorithm) Algorithms.ES512;
        Assertions.assertEquals(521, alg.getMinBitLength());

        byte[] privateKey = this.getPrivateKey("junit-ecdsa-p521");
        byte[] publicKey = this.getPublicKey("junit-ecdsa-p521");

        byte[] data = new byte[] { 0x00, 0x01, 0x02 };

        String sig = alg.getSignature(privateKey, data);
        Assertions.assertNotNull(sig);

        boolean result = alg.isSignatureValid(publicKey, data, sig);
        Assertions.assertTrue(result);
    }

    @Test
    public void test_signAndVerify_verifyMismatch() {
        EcdsaAlgorithm alg = (EcdsaAlgorithm) Algorithms.ES256;

        byte[] privateKey = this.getPrivateKey("junit-ecdsa-p256");
        byte[] publicKey = this.getPublicKey("junit-ecdsa-p384");

        byte[] data = new byte[] { 0x00, 0x01, 0x02 };

        String sig = alg.getSignature(privateKey, data);
        Assertions.assertNotNull(sig);

        boolean result = alg.isSignatureValid(publicKey, data, sig);
        Assertions.assertFalse(result);
    }

    @Test
    public void test_keyTooShort() {
        EcdsaAlgorithm alg = (EcdsaAlgorithm) Algorithms.ES256;

        byte[] privateKey = this.getPrivateKey("junit-ecdsa-too-short");

        byte[] data = new byte[] { 0x00, 0x01, 0x02 };

        try {
            alg.getSignature(privateKey, data);
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("Key is too short", ex.getMessage());
        }
    }

    @Test
    public void test_getSignature_badKey() {
        try {
            Algorithms.ES384.getSignature(new byte[] { 0x7f }, null);
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("Error signing data", ex.getMessage());
        }
    }

    @Test
    public void test_isSignatureValid_badKey() {
        try {
            Algorithms.ES512.isSignatureValid(new byte[] { 0x7f }, null, (byte[]) null);
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("Error validating data", ex.getMessage());
        }
    }

    @Test
    public void test_isSignatureValid_invalidSignature() {
        EcdsaAlgorithm alg = (EcdsaAlgorithm) Algorithms.ES256;

        byte[] privateKey = this.getPrivateKey("junit-ecdsa-p256");
        byte[] publicKey = this.getPublicKey("junit-ecdsa-p256");

        byte[] data = new byte[] { 0x00, 0x01, 0x02 };

        String sig = alg.getSignature(privateKey, data);
        Assertions.assertNotNull(sig);

        boolean result = alg.isSignatureValid(publicKey, data, sig + "junk");
        Assertions.assertFalse(result);
    }

    @Test
    public void test_keyNotEcdsa() {
        EcdsaAlgorithm alg = (EcdsaAlgorithm) Algorithms.ES512;
        try {
            alg.isKeyTooShort(Mockito.mock(PrivateKey.class));
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("Key is not an ECPrivateKey", ex.getMessage());
        }
    }

    private byte[] getPrivateKey(String alias) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream("src/test/resources/junit.jks"), new char[0]);
            PrivateKey key = (PrivateKey) ks.getKey(alias, new char[0]);
            return key.getEncoded();
        } catch (Exception ex) {
            Assertions.fail("Unexpected exception");
            return null;
        }
    }

    private byte[] getPublicKey(String alias) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream("src/test/resources/junit.jks"), new char[0]);
            Certificate cert = ks.getCertificate(alias);
            PublicKey key = cert.getPublicKey();
            return key.getEncoded();
        } catch (Exception ex) {
            Assertions.fail("Unexpected exception");
            return null;
        }
    }
}
