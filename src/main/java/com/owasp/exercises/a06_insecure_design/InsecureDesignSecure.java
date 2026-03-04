package com.owasp.exercises.a06_insecure_design;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A06:2025 - Insecure Design (CORRECTO).
 * Rate limiting, bloqueo tras intentos fallidos, recuperación con verificación.
 */
public final class InsecureDesignSecure {

    private static final int MAX_ATTEMPTS = 5;
    private static final int LOCKOUT_SECONDS = 300;

    private final Map<String, AttemptRecord> attemptsByUser = new ConcurrentHashMap<>();

    public boolean login(String user, String password) {
        AttemptRecord record = attemptsByUser.get(user);
        if (record != null && record.lockedUntil() != null && Instant.now().isBefore(record.lockedUntil())) {
            return false;  // Bloqueado
        }
        if (record != null && record.attempts() >= MAX_ATTEMPTS) {
            attemptsByUser.put(user, new AttemptRecord(0, Instant.now().plusSeconds(LOCKOUT_SECONDS)));
            return false;
        }
        boolean ok = "admin".equals(user) && "secret123".equals(password);
        if (ok) {
            attemptsByUser.remove(user);
            return true;
        }
        int next = (record == null ? 0 : record.attempts()) + 1;
        attemptsByUser.put(user, next >= MAX_ATTEMPTS
                ? new AttemptRecord(next, Instant.now().plusSeconds(LOCKOUT_SECONDS))
                : new AttemptRecord(next, null));
        return false;
    }

    /**
     * SEGURO: reset solo si se verifica token enviado por canal seguro (ej. email).
     */
    public void resetPasswordWithToken(String email, String token, String newPassword) {
        if (!verifyResetToken(email, token)) {
            throw new SecurityException("Token inválido o expirado");
        }
        // Actualizar contraseña...
    }

    private boolean verifyResetToken(String email, String token) {
        return token != null && token.length() > 16;  // Simplificado; en práctica verificar en almacén
    }

    private record AttemptRecord(int attempts, Instant lockedUntil) {}
}
