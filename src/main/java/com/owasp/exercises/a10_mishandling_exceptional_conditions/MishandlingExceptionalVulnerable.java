package com.owasp.exercises.a10_mishandling_exceptional_conditions;

/**
 * A10:2025 - Mishandling of Exceptional Conditions (VULNERABLE).
 * Ejemplo: revelar stack traces al usuario, tragar excepciones, respuestas genéricas que filtran info.
 * Ver: https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/
 */
public final class MishandlingExceptionalVulnerable {

    /**
     * VULNERABLE: devolver el mensaje de la excepción al cliente (puede revelar rutas, SQL, etc.).
     */
    public String handleError(Exception e) {
        return "Error: " + e.getMessage() + "\n" + stackTraceToString(e);
    }

    /**
     * VULNERABLE: tragar la excepción y devolver null; el llamador no sabe qué falló.
     */
    public Integer parseId(String input) {
        try {
            return Integer.parseInt(input);
        } catch (NumberFormatException e) {
            return null;  // Se pierde la causa
        }
    }

    /**
     * VULNERABLE: en un login, revelar si el usuario existe o no ("Usuario no encontrado" vs "Contraseña incorrecta").
     */
    public String loginMessage(boolean userExists, boolean passwordOk) {
        if (!userExists) return "Usuario no encontrado";
        if (!passwordOk) return "Contraseña incorrecta";
        return "OK";
    }

    private static String stackTraceToString(Exception e) {
        var sw = new java.io.StringWriter();
        e.printStackTrace(new java.io.PrintWriter(sw));
        return sw.toString();
    }
}
