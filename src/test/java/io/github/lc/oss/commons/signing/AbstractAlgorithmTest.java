package io.github.lc.oss.commons.signing;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import io.github.lc.oss.commons.testing.AbstractTest;

public class AbstractAlgorithmTest extends AbstractTest {
    private static class TestClass extends AbstractAlgorithm {
        public TestClass(String id, String algorithm, int minLength) {
            super(id, algorithm, minLength);
        }

        @Override
        public boolean isSignatureValid(byte[] secret, byte[] data, byte[] signature) {
            return false;
        }

        @Override
        public String getSignature(byte[] secret, byte[] data) {
            return null;
        }
    }

    @Test
    public void test_id() {
        AbstractAlgorithm a = new TestClass("id", "a", 512);

        Assertions.assertEquals("id", a.getId());
    }
}
