package com.github.lc.oss.commons.signing;

import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;

public class EcdsaAlgorithm extends AbstractKeyAlgorithm {
    private final int minLenghtBytes;

    public EcdsaAlgorithm(String id, String algorithm, int minLegnth) {
        super(id, algorithm, minLegnth);
        this.minLenghtBytes = minLegnth / 8;
    }

    @Override
    protected String getKeyType() {
        return "EC";
    }

    @Override
    protected boolean isKeyTooShort(PrivateKey key) {
        if (!(key instanceof ECPrivateKey)) {
            throw new RuntimeException("Key is not an ECPrivateKey");
        }
        /*
         * Some EC algorithms result in variable lengths in Java due to BigEndian
         * storage. P-521 uses 65 bytes + 1 bit so has ~50% odds of being 66 or 65 bytes
         * with a tiny percent change of being less than 65 bytes. Allowing for 8 bits
         * of variance is typically sufficient to avoid a false positive here.
         */
        return ((ECPrivateKey) key).getS().toByteArray().length < this.minLenghtBytes - 1;
    }
}
