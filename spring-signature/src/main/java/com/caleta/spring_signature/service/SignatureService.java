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

    private final String caletaKey = "";

    private final String privateKeyPem = "";

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
