package com.github.lc.oss.commons.signing;

import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HmacAlgorithm extends AbstractAlgorithm {
    private final int minSecretLength;

    public HmacAlgorithm(String id, String algorithm, int minSecretLength) {
        super(id, algorithm, minSecretLength);

        if (minSecretLength % 8 != 0) {
            throw new IllegalArgumentException("Minimum secret length must be a multiple of 8");
        }
        this.minSecretLength = minSecretLength / 8;
    }

    @Override
    public String getSignature(byte[] secret, byte[] data) {
        return this.toBase64(this.compute(secret, data));
    }

    @Override
    public boolean isSignatureValid(byte[] secret, byte[] data, byte[] signature) {
        byte[] actual = this.compute(secret, data);
        return Arrays.equals(actual, signature);
    }

    private byte[] compute(byte[] secret, byte[] data) {
        if (secret == null || secret.length < this.minSecretLength) {
            throw new IllegalArgumentException(
                    String.format("Secret is too short for this algorithm. Secret must be at least %d bits.", this.minSecretLength * 8));
        }

        try {
            Mac mac = Mac.getInstance(this.getAlgorithm());
            SecretKeySpec sks = new SecretKeySpec(secret, this.getAlgorithm());
            mac.init(sks);
            return mac.doFinal(data);
        } catch (Exception ex) {
            throw new RuntimeException("Failed to calculate HMAC", ex);
        }
    }
}
