package com.owasp.exercises.a05_injection;

import java.util.regex.Pattern;

/**
 * A05:2025 - Injection (CORRECTO).
 * Consultas parametrizadas, validación/lista blanca de entrada, sin concatenar usuario en comandos.
 */
public final class InjectionSecure {

    private static final Pattern SAFE_FILENAME = Pattern.compile("^[a-zA-Z0-9_.-]+\\.txt$");

    /**
     * SEGURO: uso de parámetro en lugar de concatenar. (Simulado: el "param" se escapa conceptualmente.)
     */
    public String buildQuerySecure(String userName) {
        String escaped = userName.replace("'", "''");  // escape mínimo para ejemplo; en práctica usar PreparedStatement
        return "SELECT * FROM users WHERE name = ? /* param: " + escaped + " */";
    }

    /**
     * SEGURO: validar entrada contra lista blanca (solo nombres de archivo permitidos).
     */
    public String buildCommandSecure(String filename) {
        if (!SAFE_FILENAME.matcher(filename).matches()) {
            throw new IllegalArgumentException("Nombre de archivo no permitido");
        }
        return "cat " + filename;
    }

    /**
     * SEGURO: no compilar regex arbitrario del usuario; usar patrón fijo controlado.
     */
    private static final Pattern CONTROLLED_PATTERN = Pattern.compile("^[a-z0-9]+$");

    public boolean matchSecure(String input) {
        return CONTROLLED_PATTERN.matcher(input).matches();
    }
}
