package io.github.lc.oss.commons.signing;

public interface Algorithm {
    String getId();

    String getSignature(String secret, String data);

    String getSignature(byte[] secret, byte[] data);

    boolean isSignatureValid(String secret, String data, String signature);

    boolean isSignatureValid(byte[] secret, byte[] data, String signature);

    boolean isSignatureValid(byte[] secret, byte[] data, byte[] signature);

    int getMinBitLength();
}
