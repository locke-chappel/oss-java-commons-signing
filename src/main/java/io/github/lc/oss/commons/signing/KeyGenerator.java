package io.github.lc.oss.commons.signing;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class KeyGenerator {
    private static final Map<Algorithm, String> TYPES;
    static {
        Map<Algorithm, String> map = new HashMap<>();
        map.put(Algorithms.RS256, "RSA");
        map.put(Algorithms.RS384, "RSA");
        map.put(Algorithms.RS512, "RSA");
        map.put(Algorithms.ES256, "EC");
        map.put(Algorithms.ES256K, "EC");
        map.put(Algorithms.ES384, "EC");
        map.put(Algorithms.ES512, "EC");
        map.put(Algorithms.ED25519, "EdDSA");
        map.put(Algorithms.ED448, "EdDSA");
        TYPES = Collections.unmodifiableMap(map);
    }

    public KeyPair generate(Algorithm algorithm) {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance(KeyGenerator.TYPES.get(algorithm));
            gen.initialize(algorithm.getMinBitLength(), new SecureRandom());
            return gen.generateKeyPair();
        } catch (Exception ex) {
            throw new RuntimeException("Error generating key pair", ex);
        }
    }
}
