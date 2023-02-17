package io.github.lc.oss.commons.signing;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import io.github.lc.oss.commons.testing.AbstractTest;
import io.github.lc.oss.commons.util.IoTools;

public class UtilTest extends AbstractTest {
    @Test
    public void test_loadKeyPair() {
        KeyPair result = Util.loadKeyPair("src/test/resources/junit.jks", "junit-eddsa-ed448", new char[0]);
        Assertions.assertNotNull(result.getPrivate());
        Assertions.assertNotNull(result.getPublic());
    }

    @Test
    public void test_loadKeyPair_error() {
        try {
            Util.loadKeyPair("src/test/resources/junit.jks", "junit-eddsa-ed448", new char[] { 0x00, 0x01 });
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("Error loading KeyPair", ex.getMessage());
        }
    }

    @Test
    public void test_loadKeyPair_error_v2() {
        try {
            Util.loadKeyPair("src/test/resources/junit.jks", "junk", new char[0]);
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("Error loading KeyPair", ex.getMessage());
        }
    }

    @Test
    public void test_loadPublicKey() {
        PublicKey result = Util.loadPublicKey("src/test/resources/junit_eddsa_ed448.cer");
        Assertions.assertNotNull(result);

        String data = new String(IoTools.readFile("src/test/resources/junit_eddsa_ed448.cer"));
        PublicKey result2 = Util.loadPublicKeyFromData(data);
        Assertions.assertNotNull(result2);
        Assertions.assertEquals(result, result2);

        PublicKey result3 = Util.loadPublicKeyFromResource("junit_eddsa_ed448.cer");
        Assertions.assertNotNull(result3);
        Assertions.assertEquals(result, result3);
    }

    @Test
    public void test_loadPublicKey_error() {
        try {
            Util.loadPublicKey("src/test/resources/junit.jks");
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("Error loading public key", ex.getMessage());
        }
    }

    @Test
    public void test_loadPublicKeyResource_error() {
        try {
            Util.loadPublicKeyFromResource(null);
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("Error loading public key", ex.getMessage());
        }
    }

    @Test
    public void test_loadPublicKeyData_error() {
        try {
            Util.loadPublicKeyFromData(null);
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("Error loading public key", ex.getMessage());
        }
    }

    @Test
    public void test_loadPrivateKeyData_error() {
        try {
            Util.loadPrivateKeyFromData(null, null);
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("Error loading private key", ex.getMessage());
        }
    }

    @Test
    public void test_loadPrivateKeyData_error_v2() {
        try {
            Util.loadPrivateKeyFromData("", "junk");
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("Error loading private key", ex.getMessage());
            Assertions.assertEquals("junk KeyFactory not available", ex.getCause().getMessage());
        }
    }

    @Test
    public void test_loadPrivateKey_error_v3() {
        String data = new String(IoTools.readFile("src/test/resources/junit_rsa_256.key"));
        try {
            Util.loadPrivateKeyFromData(data, "EC");
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("Error loading private key", ex.getMessage());
            Assertions.assertEquals("java.security.InvalidKeyException: Invalid EC private key", ex.getCause().getMessage());
        }
    }

    @Test
    public void test_loadPrivateKey_rsa() {
        String data = new String(IoTools.readFile("src/test/resources/junit_rsa_256.key"));
        PrivateKey result = Util.loadPrivateKeyFromData(data, "RSA");
        Assertions.assertNotNull(result);
    }

    @Test
    public void test_loadPrivateKey_eddsa() {
        String data = new String(IoTools.readFile("src/test/resources/junit_eddsa_448.key"));
        PrivateKey result = Util.loadPrivateKeyFromData(data, "EDDSA");
        Assertions.assertNotNull(result);
    }
}
