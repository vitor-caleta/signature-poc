package com.caleta.spring_signature.service;

import org.springframework.stereotype.Service;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
public class SignatureService {

    private final String caletaKey = "-----BEGIN PUBLIC KEY-----\n"
    +"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzbkIVi2ZiIzqcYa1EI7+\n"
    +"qDyG9w2cGRKcBpDWsV0Url95ZUS2cQ11sF3SOOZEk79P2iYcYlEWuNAFwlrH5hG1\n"
    +"WNMKS/aEPRZZo4GGPZ1wvbv+dumg5DNiQay56F0Mm8LtAhKIVk2GpRk54FvtLHz/\n"
    +"65B2bIgHeJVo6E9zKil34Lm3xefWAOS0+tbHaaCe+WNO1up9RYkGtNd4xlSxwCFt\n"
    +"bYNcYAF1xF8qZctJOD2dS+XkbQ7w0CqYZUAM+OIKb2ZO4Fu32O9jZwrgHXc9/YxL\n"
    +"5BWm3DrrEwBCBMFuzwFbXvv1HbzvPAzw/N12amCrJZ1eG0d984W8SpvVevYTlORE\n"
    +"8QIDAQAB\n"
    +"-----END PUBLIC KEY-----";

    private final String privateKeyPem = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    +"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\n"
    +"-----END OPENSSH PRIVATE KEY-----"
    ;

    public boolean verifySignature(byte[] rawBody, String header) {
        try {
            byte[] signatureBytes = Base64.getDecoder().decode(header);
            byte[] hash = sha256(rawBody);
    
            PublicKey publicKey = getPublicKey(caletaKey); // A linha que estava dando erro
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(hash);
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            e.printStackTrace(); // Para ajudar a identificar o erro
            return false;
        }
    }

    public byte[] createSignature() {
        try {
            PrivateKey privateKey = getPrivateKey(privateKeyPem);
            Map<String, String> payload = new HashMap<>();
            payload.put("game_code", "cg_sample");
            payload.put("operator_id", "sample");

            byte[] jsonPayload = new ObjectMapper().writeValueAsBytes(payload);
            byte[] hash = sha256(jsonPayload);

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(hash);
            return signature.sign();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] sha256(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }

    private PublicKey getPublicKey(String key) throws Exception {
        // Remover os cabeçalhos e espaços
        String cleanKey = key
                .replaceAll("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
    
        byte[] keyBytes = Base64.getDecoder().decode(cleanKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    private PrivateKey getPrivateKey(String key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(key.replaceAll("-----[A-Z ]-----", "").replaceAll("\\s", ""));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }
}
