package com.github.lc.oss.commons.signing;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.github.lc.oss.commons.testing.AbstractTest;

public class KeyGeneratorTest extends AbstractTest {
    @Test
    public void test_all() {
        KeyGenerator generator = new KeyGenerator();

        for (Algorithm algorithm : Algorithms.all()) {
            if (algorithm.getId().startsWith("HS")) {
                try {
                    generator.generate(algorithm);
                    Assertions.fail("Expected exception");
                } catch (RuntimeException ex) {
                    Assertions.assertEquals("Error generating key pair", ex.getMessage());
                }
            } else {
                Assertions.assertTrue(algorithm instanceof AbstractKeyAlgorithm, String.format("%s is not an AbstractKeyAlgorithm", algorithm.getId()));
                KeyPair result = generator.generate(algorithm);
                Assertions.assertNotNull(result);
                Assertions.assertFalse(((AbstractKeyAlgorithm) algorithm).isKeyTooShort(result.getPrivate()));

                if (algorithm.getId().startsWith("RS")) {
                    Assertions.assertTrue(result.getPrivate() instanceof RSAPrivateKey);
                    Assertions.assertTrue(result.getPublic() instanceof RSAPublicKey);
                } else if (algorithm.getId().startsWith("ES")) {
                    Assertions.assertTrue(result.getPrivate() instanceof ECPrivateKey);
                    Assertions.assertTrue(result.getPublic() instanceof ECPublicKey);
                } else if (algorithm.getId().startsWith("ED")) {
                    Assertions.assertTrue(result.getPrivate() instanceof EdECPrivateKey);
                    Assertions.assertTrue(result.getPublic() instanceof EdECPublicKey);
                } else {
                    Assertions.fail("Unexpected algorithm");
                }
            }
        }
    }
}
