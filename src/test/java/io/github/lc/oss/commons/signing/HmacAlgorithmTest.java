package io.github.lc.oss.commons.signing;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import io.github.lc.oss.commons.testing.AbstractTest;

public class HmacAlgorithmTest extends AbstractTest {
    @Test
    public void test_badLength() {
        try {
            new HmacAlgorithm("HS256", "HmacSHA256", 9);
            Assertions.fail("Expected exception");
        } catch (IllegalArgumentException ex) {
            Assertions.assertEquals("Minimum secret length must be a multiple of 8", ex.getMessage());
        }
    }

    @Test
    public void test_compute_noSecret() {
        HmacAlgorithm alg = new HmacAlgorithm("HS256", "HmacSHA256", 256);

        byte[] data = new byte[] { 0x00, 0x01, 0x02 };

        try {
            alg.getSignature(null, data);
            Assertions.fail("Expected exception");
        } catch (IllegalArgumentException ex) {
            Assertions.assertEquals("Secret is too short for this algorithm. Secret must be at least 256 bits.", ex.getMessage());
        }
    }

    @Test
    public void test_compute_secretTooShort() {
        HmacAlgorithm alg = new HmacAlgorithm("HS256", "HmacSHA256", 256);

        byte[] data = new byte[] { 0x00, 0x01, 0x02 };

        try {
            alg.getSignature(new byte[] { 0x00 }, data);
            Assertions.fail("Expected exception");
        } catch (IllegalArgumentException ex) {
            Assertions.assertEquals("Secret is too short for this algorithm. Secret must be at least 256 bits.", ex.getMessage());
        }
    }

    @Test
    public void test_compute_exception() {
        HmacAlgorithm alg = new HmacAlgorithm("HS256", "junk", 256);
        String secreStr = "At-least-32-chars-are-required-for-a-256-bit-hmac-secret";

        byte[] data = new byte[] { 0x00, 0x01, 0x02 };

        try {
            alg.getSignature(secreStr.getBytes(StandardCharsets.UTF_8), data);
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("Failed to calculate HMAC", ex.getMessage());
        }
    }

    @Test
    public void test_compute() {
        HmacAlgorithm alg = new HmacAlgorithm("HS256", "HmacSHA256", 256);

        String secreStr = "At-least-32-chars-are-required-for-a-256-bit-hmac-secret";

        byte[] data = new byte[] { 0x00, 0x01, 0x02 };

        String result = alg.getSignature(secreStr.getBytes(StandardCharsets.UTF_8), data);
        Assertions.assertEquals("WDerFNu1CUlHD+/YzSx+XN1V9h/DoQLbuAg8vEQCdMM", result);
    }

    @Test
    public void test_signAndVerify_strings() {
        HmacAlgorithm alg = (HmacAlgorithm) Algorithms.HS256;

        String secreStr = java.util.Base64.getEncoder()
                .encodeToString("At-least-32-chars-are-required-for-a-256-bit-hmac-secret".getBytes(StandardCharsets.UTF_8));

        String data = "test data";

        String sig = alg.getSignature(secreStr, data);
        Assertions.assertNotNull(sig);

        boolean result = alg.isSignatureValid(secreStr, data, sig);
        Assertions.assertTrue(result);
    }
}
