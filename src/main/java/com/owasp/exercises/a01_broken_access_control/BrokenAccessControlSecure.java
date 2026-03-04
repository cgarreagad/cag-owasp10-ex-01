package com.owasp.exercises.a01_broken_access_control;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A01:2025 - Broken Access Control (CORRECTO).
 * Se verifica que el usuario actual tenga permiso sobre el recurso antes de devolverlo.
 */
public final class BrokenAccessControlSecure {

    private final Map<String, Document> documents = new ConcurrentHashMap<>();

    public BrokenAccessControlSecure() {
        documents.put("doc-1", new Document("doc-1", "user-alice", "Contenido confidencial de Alice"));
        documents.put("doc-2", new Document("doc-2", "user-bob", "Contenido confidencial de Bob"));
    }

    /**
     * SEGURO: solo se devuelve el documento si el usuario actual es el propietario
     * o tiene un rol que permita acceso (ej. admin). En caso contrario Optional.empty().
     */
    public Optional<Document> getDocument(String documentId, String currentUserId, boolean isAdmin) {
        Document doc = documents.get(documentId);
        if (doc == null) {
            return Optional.empty();
        }
        if (doc.ownerId().equals(currentUserId) || isAdmin) {
            return Optional.of(doc);
        }
        return Optional.empty();
    }

    public record Document(String id, String ownerId, String content) {}
}
