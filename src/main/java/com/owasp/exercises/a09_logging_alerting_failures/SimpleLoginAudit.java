package com.owasp.exercises.a09_logging_alerting_failures;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Implementación simple de LoginAudit para los ejemplos A09.
 */
public final class SimpleLoginAudit implements LoggingAlertingSecure.LoginAudit {

    private final Map<String, Integer> failedAttempts = new ConcurrentHashMap<>();

    @Override
    public void recordFailedAttempt(String user) {
        failedAttempts.merge(user, 1, Integer::sum);
    }

    @Override
    public int getFailedAttempts(String user) {
        return failedAttempts.getOrDefault(user, 0);
    }
}
