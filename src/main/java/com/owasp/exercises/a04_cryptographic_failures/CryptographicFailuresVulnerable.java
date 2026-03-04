package com.owasp.exercises.a04_cryptographic_failures;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * A04:2025 - Cryptographic Failures (VULNERABLE).
 * Ejemplo: MD5 para contraseñas, almacenar en claro, algoritmo débil.
 * Ver: https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/
 */
public final class CryptographicFailuresVulnerable {

    /**
     * VULNERABLE: MD5 es inseguro para contraseñas (colisiones, rápido).
     */
    public String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hash);
    }

    /**
     * VULNERABLE: "encriptación" con XOR trivial, reversible y sin clave robusta.
     */
    public String encryptTrivial(String plain, byte key) {
        byte[] bytes = plain.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] ^= key;
        }
        return Base64.getEncoder().encodeToString(bytes);
    }
}
