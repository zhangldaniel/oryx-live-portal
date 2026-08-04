package main

import "testing"

func TestLoadConfigRequiresStrongGatewaySecret(t *testing.T) {
	t.Setenv("AUTHZ_GATEWAY_SECRET", "short")
	t.Setenv("PORTAL_ADMIN_EMAILS", "admin@example.com")

	if _, err := loadConfig(); err == nil {
		t.Fatal("loadConfig() accepted a gateway secret shorter than 32 characters")
	}
}
