package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestHydrateCodexTokenStorage(t *testing.T) {
	keyring, err := codex.NewResponsesCompactionKeyring("account-a")
	if err != nil {
		t.Fatalf("NewResponsesCompactionKeyring: %v", err)
	}
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Metadata: map[string]any{
			"type":            "codex",
			"account_id":      "account-a",
			"access_token":    "synthetic-access-token",
			"custom_metadata": "preserved",
			codex.ResponsesCompactionKeyringMetadataKey: keyring,
		},
	}
	hydrateCodexTokenStorage(auth)
	storage, ok := auth.Storage.(*codex.CodexTokenStorage)
	if !ok || storage.ResponsesCompactionKeyring == nil || storage.ResponsesCompactionKeyring.RootKey != keyring.RootKey {
		t.Fatal("valid account keyring was not hydrated into typed storage")
	}
	if _, exists := auth.Metadata[codex.ResponsesCompactionKeyringMetadataKey]; exists {
		t.Fatal("reserved keyring remained in runtime metadata")
	}
	if auth.Metadata["custom_metadata"] != "preserved" {
		t.Fatal("unrelated metadata was not preserved")
	}
	runtimeJSON, err := json.Marshal(auth)
	if err != nil {
		t.Fatalf("marshal runtime auth: %v", err)
	}
	if strings.Contains(string(runtimeJSON), codex.ResponsesCompactionKeyringMetadataKey) || strings.Contains(string(runtimeJSON), keyring.RootKey) {
		t.Fatal("runtime auth JSON exposed the compaction keyring")
	}
	credentialPath := filepath.Join(t.TempDir(), "codex.json")
	if err = storage.SaveTokenToFile(credentialPath); err != nil {
		t.Fatalf("SaveTokenToFile: %v", err)
	}
	credentialBytes, err := os.ReadFile(credentialPath)
	if err != nil {
		t.Fatalf("read saved credential: %v", err)
	}
	credential := make(map[string]any)
	if err = json.Unmarshal(credentialBytes, &credential); err != nil {
		t.Fatalf("unmarshal saved credential: %v", err)
	}
	savedKeyring, ok := codex.ResponsesCompactionKeyringFromValue(credential[codex.ResponsesCompactionKeyringMetadataKey])
	if !ok || savedKeyring.RootKey != keyring.RootKey {
		t.Fatal("saved credential did not retain the typed compaction keyring")
	}
}

func TestFilesystemStoresHydrateCodexTokenStorage(t *testing.T) {
	keyring, err := codex.NewResponsesCompactionKeyring("account-a")
	if err != nil {
		t.Fatalf("NewResponsesCompactionKeyring: %v", err)
	}
	credential, err := json.Marshal(map[string]any{
		"type":            "codex",
		"account_id":      "account-a",
		"access_token":    "synthetic-access-token",
		"custom_metadata": "preserved",
		codex.ResponsesCompactionKeyringMetadataKey: keyring,
	})
	if err != nil {
		t.Fatalf("marshal credential fixture: %v", err)
	}
	tests := []struct {
		name string
		load func(string, string) (*cliproxyauth.Auth, error)
	}{
		{
			name: "git",
			load: func(path, baseDir string) (*cliproxyauth.Auth, error) {
				return (&GitTokenStore{}).readAuthFile(path, baseDir)
			},
		},
		{
			name: "object",
			load: func(path, baseDir string) (*cliproxyauth.Auth, error) {
				return (&ObjectTokenStore{}).readAuthFile(path, baseDir)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			baseDir := t.TempDir()
			credentialPath := filepath.Join(baseDir, "codex.json")
			if errWrite := os.WriteFile(credentialPath, credential, 0o600); errWrite != nil {
				t.Fatalf("write credential fixture: %v", errWrite)
			}
			auth, errLoad := test.load(credentialPath, baseDir)
			if errLoad != nil {
				t.Fatalf("load credential: %v", errLoad)
			}
			storage, ok := auth.Storage.(*codex.CodexTokenStorage)
			if !ok || storage.ResponsesCompactionKeyring == nil || storage.ResponsesCompactionKeyring.RootKey != keyring.RootKey {
				t.Fatal("filesystem loader did not hydrate the valid account keyring")
			}
			if _, exists := auth.Metadata[codex.ResponsesCompactionKeyringMetadataKey]; exists {
				t.Fatal("filesystem loader exposed the keyring in runtime metadata")
			}
		})
	}
}

func TestHydrateCodexTokenStorageRejectsForeignAccountKeyring(t *testing.T) {
	keyring, err := codex.NewResponsesCompactionKeyring("account-b")
	if err != nil {
		t.Fatalf("NewResponsesCompactionKeyring: %v", err)
	}
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Metadata: map[string]any{
			"type":            "codex",
			"account_id":      "account-a",
			"custom_metadata": "preserved",
			codex.ResponsesCompactionKeyringMetadataKey: keyring,
		},
	}
	hydrateCodexTokenStorage(auth)
	storage, ok := auth.Storage.(*codex.CodexTokenStorage)
	if !ok || storage.ResponsesCompactionKeyring != nil {
		t.Fatal("foreign account keyring was accepted")
	}
	if _, exists := auth.Metadata[codex.ResponsesCompactionKeyringMetadataKey]; exists {
		t.Fatal("foreign keyring remained in runtime metadata")
	}
	if auth.Metadata["custom_metadata"] != "preserved" {
		t.Fatal("unrelated metadata was not preserved")
	}
}

func TestHydrateCodexTokenStorageLeavesNonCodexMetadataUnchanged(t *testing.T) {
	keyring, err := codex.NewResponsesCompactionKeyring("account-a")
	if err != nil {
		t.Fatalf("NewResponsesCompactionKeyring: %v", err)
	}
	metadata := map[string]any{
		"type": "claude",
		codex.ResponsesCompactionKeyringMetadataKey: keyring,
	}
	auth := &cliproxyauth.Auth{Provider: "claude", Metadata: metadata}
	hydrateCodexTokenStorage(auth)
	if auth.Storage != nil {
		t.Fatal("non-Codex auth received Codex token storage")
	}
	if metadata[codex.ResponsesCompactionKeyringMetadataKey] != keyring {
		t.Fatal("non-Codex metadata was changed")
	}
}
