package io.github.lc.oss.commons.signing;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class Algorithms {
    public static final Algorithm HS256 = new HmacAlgorithm("HS256", "HmacSHA256", 256);
    public static final Algorithm HS384 = new HmacAlgorithm("HS384", "HmacSHA384", 384);
    public static final Algorithm HS512 = new HmacAlgorithm("HS512", "HmacSHA512", 512);

    public static final Algorithm RS256 = new RsaAlgorithm("RS256", "SHA256withRSA", 2048);
    public static final Algorithm RS384 = new RsaAlgorithm("RS384", "SHA384withRSA", 2048);
    public static final Algorithm RS512 = new RsaAlgorithm("RS512", "SHA512withRSA", 2048);

    public static final Algorithm ES256 = new EcdsaAlgorithm("ES256", "SHA256withECDSA", 256);
    public static final Algorithm ES256K = new EcdsaAlgorithm("ES256K", "SHA256withECDSA", 256);
    public static final Algorithm ES384 = new EcdsaAlgorithm("ES384", "SHA384withECDSA", 384);
    public static final Algorithm ES512 = new EcdsaAlgorithm("ES512", "SHA512withECDSA", 521);

    public static final Algorithm ED25519 = new EddsaAlgorithm("ED25519", "Ed25519", 255);
    public static final Algorithm ED448 = new EddsaAlgorithm("ED448", "Ed448", 448);

    static {
        Algorithms.register(Algorithms.HS256);
        Algorithms.register(Algorithms.HS384);
        Algorithms.register(Algorithms.HS512);

        Algorithms.register(Algorithms.RS256);
        Algorithms.register(Algorithms.RS384);
        Algorithms.register(Algorithms.RS512);

        Algorithms.register(Algorithms.ES256);
        Algorithms.register(Algorithms.ES256K);
        Algorithms.register(Algorithms.ES384);
        Algorithms.register(Algorithms.ES512);

        Algorithms.register(Algorithms.ED25519);
        Algorithms.register(Algorithms.ED448);
    }

    private static class Cache {
        public static Map<String, Algorithm> ALL = new HashMap<>();
        public static Map<String, Algorithm> HMAC = new HashMap<>();
        public static Map<String, Algorithm> KEY = new HashMap<>();
    }

    public static Set<Algorithm> all() {
        return Collections.unmodifiableSet(new HashSet<>(Cache.ALL.values()));
    }

    /**
     * @return The subset of all registered algorithms that implement an
     *         {@linkplain HmacAlgorithm} (e.g. HS256, HS384, HS512, etc.)
     */
    public static Set<Algorithm> hmacAlgorithms() {
        return Collections.unmodifiableSet(new HashSet<>(Cache.HMAC.values()));
    }

    /**
     * @return The subset of all registered algorithms that implement an
     *         {@linkplain AbstractKeyAlgorithm} (e.g. RS256, ES256, ED25519, etc.)
     */
    public static Set<Algorithm> keyAlgorithms() {
        return Collections.unmodifiableSet(new HashSet<>(Cache.KEY.values()));
    }

    public static Algorithm get(String id) {
        return Cache.ALL.get(id);
    }

    public static boolean has(String id) {
        return Cache.ALL.containsKey(id);
    }

    public static Algorithm register(Algorithm alg) {
        synchronized (Cache.ALL) {
            if (alg == null || alg.getId() == null || alg.getId().trim().equals("")) {
                throw new IllegalArgumentException("Algorithm and it's ID are required.");
            }

            if (Cache.ALL.containsKey(alg.getId())) {
                throw new RuntimeException(String.format("%s has already been registered", alg.getId()));
            }

            if (alg instanceof HmacAlgorithm) {
                Cache.HMAC.put(alg.getId(), alg);
            } else if (alg instanceof AbstractKeyAlgorithm) {
                Cache.KEY.put(alg.getId(), alg);
            }

            return Cache.ALL.put(alg.getId(), alg);
        }
    }

    public static Algorithm unregister(Algorithm alg) {
        synchronized (Cache.ALL) {
            if (alg == null || alg.getId() == null || alg.getId().trim().equals("")) {
                throw new IllegalArgumentException("Algorithm and it's ID are required.");
            }

            return Cache.ALL.remove(alg.getId());
        }
    }

    private Algorithms() {
    }
}
