package io.github.lc.oss.commons.signing;

import java.nio.charset.StandardCharsets;

public abstract class AbstractAlgorithm implements Algorithm {
    private final String algorithm;
    private final String id;
    private final int minLength;

    public AbstractAlgorithm(String id, String algorithm, int minLength) {
        this.id = id;
        this.algorithm = algorithm;
        this.minLength = minLength;
    }

    @Override
    public String getId() {
        return this.id;
    }

    @Override
    public int getMinBitLength() {
        return this.minLength;
    }

    protected String getAlgorithm() {
        return this.algorithm;
    }

    @Override
    public String getSignature(String secret, String data) {
        return this.getSignature(this.fromBase64(secret), data.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public boolean isSignatureValid(String secret, String data, String signature) {
        return this.isSignatureValid(this.fromBase64(secret), data.getBytes(StandardCharsets.UTF_8), signature);
    }

    @Override
    public boolean isSignatureValid(byte[] secret, byte[] data, String signature) {
        return this.isSignatureValid(secret, data, this.fromBase64(signature));
    }

    protected String toBase64(byte[] data) {
        return java.util.Base64.getEncoder().withoutPadding().encodeToString(data);
    }

    protected byte[] fromBase64(String data) {
        return java.util.Base64.getDecoder().decode(data);
    }
}
