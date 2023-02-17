package io.github.lc.oss.commons.signing;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import io.github.lc.oss.commons.testing.AbstractTest;

public class AlgorithmsTest extends AbstractTest {
    @Test
    public void test_caching() {

        Algorithm result = Algorithms.get(null);
        Assertions.assertNull(result);

        result = Algorithms.get("");
        Assertions.assertNull(result);

        result = Algorithms.get(" \r \n \t ");
        Assertions.assertNull(result);

        for (Algorithm a : Algorithms.all()) {
            Assertions.assertSame(a, Algorithms.get(a.getId()));
            Assertions.assertTrue(Algorithms.has(a.getId()));
        }

        final Algorithm alg = new HmacAlgorithm("id", "HMAC", 16);
        try {
            Assertions.assertNull(Algorithms.get(alg.getId()));
            Algorithms.register(alg);
            Assertions.assertSame(alg, Algorithms.get(alg.getId()));
        } finally {
            Algorithms.unregister(alg);
        }
    }

    @Test
    public void test_registerErrors() {
        Algorithm nullId = new Algorithm() {
            @Override
            public boolean isSignatureValid(byte[] secret, byte[] data, byte[] signature) {
                return false;
            }

            @Override
            public String getSignature(String secret, String data) {
                return null;
            }

            @Override
            public String getSignature(byte[] secret, byte[] data) {
                return null;
            }

            @Override
            public String getId() {
                return null;
            }

            @Override
            public int getMinBitLength() {
                return 0;
            }

            @Override
            public boolean isSignatureValid(byte[] secret, byte[] data, String signature) {
                return false;
            }

            @Override
            public boolean isSignatureValid(String secret, String data, String signature) {
                return false;
            }
        };

        Algorithm blankId = new Algorithm() {
            @Override
            public boolean isSignatureValid(byte[] secret, byte[] data, byte[] signature) {
                return false;
            }

            @Override
            public String getSignature(byte[] secret, byte[] data) {
                return null;
            }

            @Override
            public String getId() {
                return " \r \n \t ";
            }

            @Override
            public int getMinBitLength() {
                return 0;
            }

            @Override
            public boolean isSignatureValid(byte[] secret, byte[] data, String signature) {
                return false;
            }

            @Override
            public String getSignature(String secret, String data) {
                return null;
            }

            @Override
            public boolean isSignatureValid(String secret, String data, String signature) {
                return false;
            }
        };

        try {
            Algorithms.register(null);
            Assertions.fail("Expected exception");
        } catch (IllegalArgumentException ex) {
            Assertions.assertEquals("Algorithm and it's ID are required.", ex.getMessage());
        }

        try {
            Algorithms.register(nullId);
            Assertions.fail("Expected exception");
        } catch (IllegalArgumentException ex) {
            Assertions.assertEquals("Algorithm and it's ID are required.", ex.getMessage());
        }

        try {
            Algorithms.register(blankId);
            Assertions.fail("Expected exception");
        } catch (IllegalArgumentException ex) {
            Assertions.assertEquals("Algorithm and it's ID are required.", ex.getMessage());
        }
    }

    @Test
    public void test_registerTwice() {
        Assertions.assertSame(Algorithms.HS256, Algorithms.get(Algorithms.HS256.getId()));

        try {
            Algorithms.register(Algorithms.HS256);
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("HS256 has already been registered", ex.getMessage());
        }
    }

    @Test
    public void test_unregisterErrors() {
        Algorithm nullId = new Algorithm() {
            @Override
            public boolean isSignatureValid(byte[] secret, byte[] data, byte[] signature) {
                return false;
            }

            @Override
            public String getSignature(byte[] secret, byte[] data) {
                return null;
            }

            @Override
            public String getId() {
                return null;
            }

            @Override
            public int getMinBitLength() {
                return 0;
            }

            @Override
            public boolean isSignatureValid(byte[] secret, byte[] data, String signature) {
                return false;
            }

            @Override
            public String getSignature(String secret, String data) {
                return null;
            }

            @Override
            public boolean isSignatureValid(String secret, String data, String signature) {
                return false;
            }
        };

        Algorithm blankId = new Algorithm() {
            @Override
            public boolean isSignatureValid(byte[] secret, byte[] data, byte[] signature) {
                return false;
            }

            @Override
            public String getSignature(byte[] secret, byte[] data) {
                return null;
            }

            @Override
            public String getId() {
                return " \r \n \t ";
            }

            @Override
            public int getMinBitLength() {
                return 0;
            }

            @Override
            public boolean isSignatureValid(byte[] secret, byte[] data, String signature) {
                return false;
            }

            @Override
            public String getSignature(String secret, String data) {
                return null;
            }

            @Override
            public boolean isSignatureValid(String secret, String data, String signature) {
                return false;
            }
        };

        try {
            Algorithms.unregister(null);
            Assertions.fail("Expected exception");
        } catch (IllegalArgumentException ex) {
            Assertions.assertEquals("Algorithm and it's ID are required.", ex.getMessage());
        }

        try {
            Algorithms.unregister(nullId);
            Assertions.fail("Expected exception");
        } catch (IllegalArgumentException ex) {
            Assertions.assertEquals("Algorithm and it's ID are required.", ex.getMessage());
        }

        try {
            Algorithms.unregister(blankId);
            Assertions.fail("Expected exception");
        } catch (IllegalArgumentException ex) {
            Assertions.assertEquals("Algorithm and it's ID are required.", ex.getMessage());
        }
    }
}
