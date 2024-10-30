package com.caleta.spring_signature.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.caleta.spring_signature.service.SignatureService;

import java.nio.charset.StandardCharsets;

@RestController
public class SignatureController {
    private SignatureService signatureService;

    @PostMapping("/verify")
    public ResponseEntity<Boolean> verifySignature(
            @RequestHeader("X-Auth-Signature") String signature,
            @RequestBody String rawBody) {

       
        byte[] rawBodyBytes = rawBody.getBytes(StandardCharsets.UTF_8);
        boolean result = signatureService.verifySignature(rawBodyBytes, signature);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/create")
    public ResponseEntity<byte[]> createSignature() {
        byte[] result = signatureService.createSignature();
        return ResponseEntity.ok(result);
    }
}
