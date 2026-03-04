package com.owasp.exercises.a03_software_supply_chain;

import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * A03:2025 - Software Supply Chain (CORRECTO).
 * Solo se permiten orígenes en lista blanca; uso de URI y esquema controlado.
 */
public final class SupplyChainSecure {

    private final Set<String> allowedHosts;

    public SupplyChainSecure(Set<String> allowedHosts) {
        this.allowedHosts = Set.copyOf(allowedHosts);
    }

    /**
     * SEGURO: solo se aceptan URLs de hosts permitidos y esquema HTTPS.
     */
    public String loadScriptFromUrl(String urlString) throws Exception {
        URI uri = URI.create(urlString);
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            throw new SecurityException("Solo se permiten URLs HTTPS");
        }
        String host = uri.getHost();
        if (host == null || !allowedHosts.contains(host)) {
            throw new SecurityException("Host no permitido: " + host);
        }
        try (InputStream in = uri.toURL().openStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
