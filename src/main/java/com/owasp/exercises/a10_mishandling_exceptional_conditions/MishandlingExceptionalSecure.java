package com.owasp.exercises.a10_mishandling_exceptional_conditions;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A10:2025 - Mishandling of Exceptional Conditions (CORRECTO).
 * No exponer stack traces ni detalles internos al usuario; log interno; mensajes genéricos.
 */
public final class MishandlingExceptionalSecure {

    private static final Logger LOG = Logger.getLogger(MishandlingExceptionalSecure.class.getName());

    /**
     * SEGURO: log completo en servidor; al cliente solo mensaje genérico sin detalles.
     */
    public String handleError(Exception e) {
        LOG.log(Level.SEVERE, "Error interno", e);
        return "Ha ocurrido un error. Por favor, inténtelo más tarde.";
    }

    /**
     * SEGURO: propagar o lanzar excepción de dominio con mensaje controlado; no devolver null sin contexto.
     */
    public int parseId(String input) {
        try {
            return Integer.parseInt(input);
        } catch (NumberFormatException e) {
            LOG.fine("parseId failed for input: " + (input != null ? "length=" + input.length() : "null"));
            throw new IllegalArgumentException("Identificador inválido");
        }
    }

    /**
     * SEGURO: mismo mensaje para "usuario no existe" y "contraseña incorrecta" para no revelar si el usuario existe.
     */
    public String loginMessage(boolean userExists, boolean passwordOk) {
        if (!userExists || !passwordOk) {
            return "Credenciales incorrectas";
        }
        return "OK";
    }
}
