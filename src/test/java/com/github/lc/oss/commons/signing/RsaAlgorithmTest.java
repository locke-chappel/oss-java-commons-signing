package com.github.lc.oss.commons.signing;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.github.lc.oss.commons.testing.AbstractTest;

public class RsaAlgorithmTest extends AbstractTest {
    @Test
    public void test_signAndVerify_strings() {
        RsaAlgorithm alg = (RsaAlgorithm) Algorithms.RS256;
        Assertions.assertEquals(2048, alg.getMinBitLength());

        String privateKey = java.util.Base64.getEncoder().encodeToString(this.getPrivateKey("junit-rsa-256"));
        String publicKey = java.util.Base64.getEncoder().encodeToString(this.getPublicKey("junit-rsa-256"));

        String data = "test data";

        String sig = alg.getSignature(privateKey, data);
        Assertions.assertNotNull(sig);

        boolean result = alg.isSignatureValid(publicKey, data, sig);
        Assertions.assertTrue(result);
    }

    @Test
    public void test_signAndVerify_sha256() {
        RsaAlgorithm alg = (RsaAlgorithm) Algorithms.RS256;
        Assertions.assertEquals(2048, alg.getMinBitLength());

        byte[] privateKey = this.getPrivateKey("junit-rsa-256");
        byte[] publicKey = this.getPublicKey("junit-rsa-256");

        byte[] data = new byte[] { 0x00, 0x01, 0x02 };

        String sig = alg.getSignature(privateKey, data);
        Assertions.assertEquals(
                "WhuRnstz19tDQCAE6oMljz0sVEUZojFaJeebHrOWAWjNLzeYzVVeg15elQClbTN5J0mEOKzjOWWioXsdzeS0kyIKUE98gpO0ruKWXZg8yOCiFWcwbQea0HVOgzBNGFptT/cxeQrjXSb9ZbTcvFnwBYl/6xf+TWptFPzWXrh/U8jCKILXjnX9VLCubzVVEtKV9VzskYBjeedROJ10l/iBC5foOSDEv35gQ4xVck4S2D+EaJ2PjcXHFDP/y1BrwsLlQKjsZsKT69sGxqLwuV+b4F7RIQXz0FA7nrnAaiExQce83FuUTGxwMIvN7pIlj859WRfbEMnXpnZyPoHkocfW3A",
                sig);

        boolean result = alg.isSignatureValid(publicKey, data, sig);
        Assertions.assertTrue(result);
    }

    @Test
    public void test_signAndVerify_sha384() {
        RsaAlgorithm alg = (RsaAlgorithm) Algorithms.RS384;
        Assertions.assertEquals(2048, alg.getMinBitLength());

        byte[] privateKey = this.getPrivateKey("junit-rsa-384");
        byte[] publicKey = this.getPublicKey("junit-rsa-384");

        byte[] data = new byte[] { 0x00, 0x01, 0x02 };

        String sig = alg.getSignature(privateKey, data);
        Assertions.assertEquals(
                "DPdftYfJmqspird9pEG0mfxtEH6gvGtqsEKrltwNiYum5dNM5Df40KLpiDoM61VCHv7sqw7iPFFhn2x4KE3zweR6a0HofU7wgWn4RFKtLxGK82CqY6PpCtIWnjlbeXRyw808NFTY0VVE9+RVJJ9TiUMCg1i5OcMXBdmDvZLFaQ26XeeC+PdLBr8+076/p1vLl9XbPPlJDkigiIYJPRbdPlD5BPFVhjy8iw8bqW5VVvuSVUUr9a9UBXSfKGzpXZKF604Umwqmgi5aCLMqTY0SwX0xg6tlYo4M6R8giqT0N9s7zNd+xeEsLktDRWvLtv+pw+GhKNNKGYJn0T/8QP+roA",
                sig);

        boolean result = alg.isSignatureValid(publicKey, data, sig);
        Assertions.assertTrue(result);
    }

    @Test
    public void test_signAndVerify_sha512() {
        RsaAlgorithm alg = (RsaAlgorithm) Algorithms.RS512;
        Assertions.assertEquals(2048, alg.getMinBitLength());

        byte[] privateKey = this.getPrivateKey("junit-rsa-512");
        byte[] publicKey = this.getPublicKey("junit-rsa-512");

        byte[] data = new byte[] { 0x00, 0x01, 0x02 };

        String sig = alg.getSignature(privateKey, data);
        Assertions.assertEquals(
                "CfWkI1wKJNSa4TVeywL/CCUjJY6SbyVuboC+sVEcQeXaJwsL0/11hurEAzPDerzJwfaz7rdGQVc02LeWKi0gGkpTMdHToxmIV4y6aDujrzKpj3hY9uz5uO4hRoVyrBpbzzyde9Cw7n2TWrQ2yqLbdMWuei45iuQYBtFL/yS7YlNBAkxbBVxWJHZ7uEA4jW5PJ0cgFLMurmnpjPqamKX8rQI5emCSQvZDlgPfTQKK3kX9fwcb/5xxBH7LpOO25kxfGlIFANraIwB5mO1JEb8yo+2LglY1sNipOtIAFCCF5dn+wPyO+9y5PbXIkufFKfPh3sWHqm0jLMN62R+h9L7JIw",
                sig);

        boolean result = alg.isSignatureValid(publicKey, data, sig);
        Assertions.assertTrue(result);
    }

    @Test
    public void test_signAndVerify_mismatch() {
        RsaAlgorithm alg = (RsaAlgorithm) Algorithms.RS256;

        byte[] privateKey = this.getPrivateKey("junit-rsa-256");
        byte[] publicKey = this.getPublicKey("junit-rsa-384");

        byte[] data = new byte[] { 0x00, 0x01, 0x02 };

        String sig = alg.getSignature(privateKey, data);
        Assertions.assertEquals(
                "WhuRnstz19tDQCAE6oMljz0sVEUZojFaJeebHrOWAWjNLzeYzVVeg15elQClbTN5J0mEOKzjOWWioXsdzeS0kyIKUE98gpO0ruKWXZg8yOCiFWcwbQea0HVOgzBNGFptT/cxeQrjXSb9ZbTcvFnwBYl/6xf+TWptFPzWXrh/U8jCKILXjnX9VLCubzVVEtKV9VzskYBjeedROJ10l/iBC5foOSDEv35gQ4xVck4S2D+EaJ2PjcXHFDP/y1BrwsLlQKjsZsKT69sGxqLwuV+b4F7RIQXz0FA7nrnAaiExQce83FuUTGxwMIvN7pIlj859WRfbEMnXpnZyPoHkocfW3A",
                sig);

        boolean result = alg.isSignatureValid(publicKey, data, sig);
        Assertions.assertFalse(result);
    }

    @Test
    public void test_keyTooShort() {
        RsaAlgorithm alg = (RsaAlgorithm) Algorithms.RS256;

        byte[] privateKey = this.getPrivateKey("junit-rsa-too-short");

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
            Algorithms.RS384.getSignature(new byte[] { 0x7f }, null);
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("Error signing data", ex.getMessage());
        }
    }

    @Test
    public void test_isSignatureValid_badKey() {
        try {
            Algorithms.RS512.isSignatureValid(new byte[] { 0x7f }, null, (byte[]) null);
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("Error validating data", ex.getMessage());
        }
    }

    @Test
    public void test_isSignatureValid_invalidSignature() {
        RsaAlgorithm alg = (RsaAlgorithm) Algorithms.RS256;

        byte[] privateKey = this.getPrivateKey("junit-rsa-256");
        byte[] publicKey = this.getPublicKey("junit-rsa-256");

        byte[] data = new byte[] { 0x00, 0x01, 0x02 };

        String sig = alg.getSignature(privateKey, data);
        Assertions.assertEquals(
                "WhuRnstz19tDQCAE6oMljz0sVEUZojFaJeebHrOWAWjNLzeYzVVeg15elQClbTN5J0mEOKzjOWWioXsdzeS0kyIKUE98gpO0ruKWXZg8yOCiFWcwbQea0HVOgzBNGFptT/cxeQrjXSb9ZbTcvFnwBYl/6xf+TWptFPzWXrh/U8jCKILXjnX9VLCubzVVEtKV9VzskYBjeedROJ10l/iBC5foOSDEv35gQ4xVck4S2D+EaJ2PjcXHFDP/y1BrwsLlQKjsZsKT69sGxqLwuV+b4F7RIQXz0FA7nrnAaiExQce83FuUTGxwMIvN7pIlj859WRfbEMnXpnZyPoHkocfW3A",
                sig);

        boolean result = alg.isSignatureValid(publicKey, data, sig + "junk");
        Assertions.assertFalse(result);
    }

    @Test
    public void test_keyNotRsa() {
        RsaAlgorithm alg = (RsaAlgorithm) Algorithms.RS256;
        try {
            alg.isKeyTooShort(Mockito.mock(PrivateKey.class));
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("Key is not an RSAPrivateKey", ex.getMessage());
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
