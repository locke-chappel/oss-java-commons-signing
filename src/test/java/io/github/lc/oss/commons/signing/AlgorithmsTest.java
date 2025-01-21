package io.github.lc.oss.commons.signing;

import java.util.HashSet;
import java.util.Set;

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

            Assertions.assertTrue(Algorithms.hmacAlgorithms().contains(alg));
            Assertions.assertFalse(Algorithms.keyAlgorithms().contains(alg));
        } finally {
            Algorithms.unregister(alg);
        }

        final Algorithm alg2 = new AbstractAlgorithm("id2", "SuperCool", 1337) {
            @Override
            public boolean isSignatureValid(byte[] secret, byte[] data, byte[] signature) {
                return false;
            }

            @Override
            public String getSignature(byte[] secret, byte[] data) {
                return null;
            }
        };
        try {
            Assertions.assertNull(Algorithms.get(alg2.getId()));
            Algorithms.register(alg2);
            Assertions.assertSame(alg2, Algorithms.get(alg2.getId()));

            Assertions.assertFalse(Algorithms.hmacAlgorithms().contains(alg2));
            Assertions.assertFalse(Algorithms.keyAlgorithms().contains(alg2));
        } finally {
            Algorithms.unregister(alg2);
        }

        Set<Algorithm> a = new HashSet<>(Algorithms.hmacAlgorithms());
        Set<Algorithm> b = new HashSet<>(Algorithms.keyAlgorithms());
        Assertions.assertTrue(a.retainAll(b));
        Assertions.assertTrue(a.isEmpty());

        a = new HashSet<>(Algorithms.hmacAlgorithms());
        b = new HashSet<>(Algorithms.keyAlgorithms());
        Assertions.assertTrue(b.retainAll(a));
        Assertions.assertTrue(b.isEmpty());
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
