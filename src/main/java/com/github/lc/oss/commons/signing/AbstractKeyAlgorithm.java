package com.github.lc.oss.commons.signing;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public abstract class AbstractKeyAlgorithm extends AbstractAlgorithm {

    protected abstract String getKeyType();

    protected abstract boolean isKeyTooShort(PrivateKey key);

    public AbstractKeyAlgorithm(String id, String algorithm, int minLength) {
        super(id, algorithm, minLength);
    }

    @Override
    public String getSignature(byte[] secret, byte[] data) {
        try {
            PrivateKey key = KeyFactory.getInstance(this.getKeyType()).generatePrivate(new PKCS8EncodedKeySpec(secret));
            if (this.isKeyTooShort(key)) {
                throw new RuntimeException("Key is too short");
            }
            Signature signature = Signature.getInstance(this.getAlgorithm());
            signature.initSign(key);
            signature.update(data);
            return this.toBase64(signature.sign());
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | SignatureException | InvalidKeyException ex) {
            throw new RuntimeException("Error signing data", ex);
        }
    }

    @Override
    public boolean isSignatureValid(byte[] secret, byte[] data, byte[] signature) {
        try {
            PublicKey key = KeyFactory.getInstance(this.getKeyType()).generatePublic(new X509EncodedKeySpec(secret));
            Signature sig = Signature.getInstance(this.getAlgorithm());
            sig.initVerify(key);
            sig.update(data);
            return sig.verify(signature);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new RuntimeException("Error validating data", ex);
        } catch (SignatureException e) {
            return false;
        }
    }
}
