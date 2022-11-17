package com.github.lc.oss.commons.signing;

import java.security.PrivateKey;
import java.security.interfaces.EdECPrivateKey;

public class EddsaAlgorithm extends AbstractKeyAlgorithm {
    private final int minLenghtBytes;

    public EddsaAlgorithm(String id, String algorithm, int minLegnth) {
        super(id, algorithm, minLegnth);
        this.minLenghtBytes = minLegnth / 8;
    }

    @Override
    protected String getKeyType() {
        return "EdDSA";
    }

    @Override
    protected boolean isKeyTooShort(PrivateKey key) {
        if (!(key instanceof EdECPrivateKey)) {
            throw new RuntimeException("Key is not an EdECPrivateKey");
        }
        /*
         * Some EdEC algorithms result in variable lengths in Java due to BigEndian
         * storage. P-521 uses 65 bytes + 1 bit so has ~50% odds of being 66 or 65 bytes
         * with a tiny percent change of being less than 65 bytes. Allowing for 8 bits
         * of variance is typically sufficient to avoid a false positive here.
         */
        return ((EdECPrivateKey) key).getEncoded().length < this.minLenghtBytes - 1;
    }
}
