package com.github.lc.oss.commons.signing;

import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;

public class RsaAlgorithm extends AbstractKeyAlgorithm {
    public RsaAlgorithm(String id, String algorithm, int minLength) {
        super(id, algorithm, minLength);
    }

    @Override
    protected String getKeyType() {
        return "RSA";
    }

    @Override
    protected boolean isKeyTooShort(PrivateKey key) {
        if (!(key instanceof RSAPrivateKey)) {
            throw new RuntimeException("Key is not an RSAPrivateKey");
        }
        /*
         * See ECDSA algorithm, there is a potential for BigEndian format to truncate a
         * 0x00 byte and cause the length to be falsely reported as too short.
         */
        return ((RSAPrivateKey) key).getModulus().bitLength() < this.getMinBitLength();
    }
}
