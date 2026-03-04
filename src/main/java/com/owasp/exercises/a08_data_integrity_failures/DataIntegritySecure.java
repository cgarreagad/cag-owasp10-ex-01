package com.owasp.exercises.a08_data_integrity_failures;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * A08:2025 - Software or Data Integrity (CORRECTO).
 * Verificación de firma HMAC antes de confiar en datos; evitar deserialización de orígenes no confiables.
 */
public final class DataIntegritySecure {

    private static final String HMAC_ALG = "HmacSHA256";

    /**
     * SEGURO: no deserializar objetos arbitrarios; usar DTOs/JSON con validación y firma.
     * Aquí se valida HMAC del payload antes de procesarlo.
     */
    public String processSignedPayload(String payloadBase64, String signatureBase64, byte[] secretKey)
            throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] payload = Base64.getDecoder().decode(payloadBase64);
        byte[] receivedSig = Base64.getDecoder().decode(signatureBase64);
        Mac mac = Mac.getInstance(HMAC_ALG);
        mac.init(new SecretKeySpec(secretKey, HMAC_ALG));
        byte[] expectedSig = mac.doFinal(payload);
        if (!java.security.MessageDigest.isEqual(receivedSig, expectedSig)) {
            throw new SecurityException("Firma inválida: integridad comprometida");
        }
        return new String(payload, StandardCharsets.UTF_8);
    }

    /**
     * Genera firma para un payload (para pruebas o en el emisor).
     */
    public static String signPayload(byte[] payload, byte[] secretKey) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(HMAC_ALG);
        mac.init(new SecretKeySpec(secretKey, HMAC_ALG));
        return Base64.getEncoder().encodeToString(mac.doFinal(payload));
    }
}
