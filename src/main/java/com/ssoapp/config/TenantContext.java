package com.ssoapp.config;

public class TenantContext {
    private static final ThreadLocal<Long> currentOrganizationId = new ThreadLocal<>();

    public static void setOrganizationId(Long organizationId) {
        currentOrganizationId.set(organizationId);
    }

    public static Long getOrganizationId() {
        return currentOrganizationId.get();
    }

    public static void clear() {
        currentOrganizationId.remove();
    }

    public static boolean isSuperAdmin() {
        return currentOrganizationId.get() == null;
    }
}
