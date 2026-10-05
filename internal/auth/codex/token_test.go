package codex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveTokenToFile_PreservesCustomMetadata(t *testing.T) {
	tempDir := t.TempDir()
	authFilePath := filepath.Join(tempDir, "codex-test.json")

	storage := &CodexTokenStorage{
		Type:         "codex",
		Email:        "user@example.com",
		AccessToken:  "new-access-token",
		RefreshToken: "new-refresh-token",
		IDToken:      "new-id-token",
		AccountID:    "new-account",
		Expire:       "2026-12-31T23:59:59Z",
		LastRefresh:  "2026-04-14T12:00:00Z",
	}
	storage.SetMetadata(map[string]any{
		"disabled":   false,
		"prefix":     "my-prefix",
		"websockets": false,
		"note":       "my important note",
		"proxy_url":  "http://proxy:8080",
		"weight":     float64(42),
	})

	if errSave := storage.SaveTokenToFile(authFilePath); errSave != nil {
		t.Fatalf("SaveTokenToFile() error = %v", errSave)
	}

	savedRaw, errRead := os.ReadFile(authFilePath)
	if errRead != nil {
		t.Fatalf("os.ReadFile error = %v", errRead)
	}

	var saved map[string]any
	if errUnmarshal := json.Unmarshal(savedRaw, &saved); errUnmarshal != nil {
		t.Fatalf("json.Unmarshal error = %v", errUnmarshal)
	}

	// Verify updated OAuth token fields
	if saved["access_token"] != "new-access-token" {
		t.Errorf("access_token = %v, want new-access-token", saved["access_token"])
	}
	if saved["refresh_token"] != "new-refresh-token" {
		t.Errorf("refresh_token = %v, want new-refresh-token", saved["refresh_token"])
	}
	if saved["id_token"] != "new-id-token" {
		t.Errorf("id_token = %v, want new-id-token", saved["id_token"])
	}
	if saved["account_id"] != "new-account" {
		t.Errorf("account_id = %v, want new-account", saved["account_id"])
	}

	// Verify custom fields in metadata
	if saved["prefix"] != "my-prefix" {
		t.Errorf("prefix = %v, want my-prefix", saved["prefix"])
	}
	if saved["websockets"] != false {
		t.Errorf("websockets = %v, want false", saved["websockets"])
	}
	if saved["note"] != "my important note" {
		t.Errorf("note = %v, want my important note", saved["note"])
	}
	if saved["proxy_url"] != "http://proxy:8080" {
		t.Errorf("proxy_url = %v, want http://proxy:8080", saved["proxy_url"])
	}
	if saved["weight"] != float64(42) {
		t.Errorf("weight = %v, want 42", saved["weight"])
	}
}

func TestResponsesCompactionKeyringIsRandomAndAccountBound(t *testing.T) {
	first, errFirst := NewResponsesCompactionKeyring("account-a")
	if errFirst != nil {
		t.Fatal(errFirst)
	}
	second, errSecond := NewResponsesCompactionKeyring("account-a")
	if errSecond != nil {
		t.Fatal(errSecond)
	}
	if !first.ValidForAccount("account-a") || first.ValidForAccount("account-b") {
		t.Fatal("keyring account binding is invalid")
	}
	if first.RootKey == second.RootKey {
		t.Fatal("separate logins reused the same random root")
	}
	unsupported := *first
	unsupported.Version++
	if unsupported.ValidForAccount("account-a") {
		t.Fatal("unsupported keyring version was accepted")
	}
}

func TestCodexTokenStoragePreservesFreshRootAndHidesMetadataCopy(t *testing.T) {
	fresh, errFresh := NewResponsesCompactionKeyring("account-a")
	if errFresh != nil {
		t.Fatal(errFresh)
	}
	old, errOld := NewResponsesCompactionKeyring("account-a")
	if errOld != nil {
		t.Fatal(errOld)
	}
	storage := &CodexTokenStorage{AccountID: "account-a", ResponsesCompactionKeyring: fresh}
	metadata := map[string]any{ResponsesCompactionKeyringMetadataKey: old, "prefix": "team"}
	storage.SetMetadata(metadata)
	if storage.ResponsesCompactionKeyring.RootKey != fresh.RootKey {
		t.Fatal("existing metadata replaced the fresh login root")
	}
	if _, exists := metadata[ResponsesCompactionKeyringMetadataKey]; exists {
		t.Fatal("reserved root remained in runtime metadata")
	}
	if _, exists := storage.Metadata[ResponsesCompactionKeyringMetadataKey]; exists {
		t.Fatal("reserved root was copied into token metadata")
	}
	storage.AccountID = "account-b"
	storage.SetMetadata(map[string]any{"prefix": "team"})
	if storage.ResponsesCompactionKeyring != nil {
		t.Fatal("foreign-account root survived an account replacement")
	}
	foreign, errForeign := NewResponsesCompactionKeyring("account-b")
	if errForeign != nil {
		t.Fatal(errForeign)
	}
	metadataStorage := &CodexTokenStorage{AccountID: "account-a"}
	metadataStorage.SetMetadata(map[string]any{ResponsesCompactionKeyringMetadataKey: foreign})
	if metadataStorage.ResponsesCompactionKeyring != nil {
		t.Fatal("metadata introduced a keyring bound to another account")
	}
}

func TestCodexTokenStorageRoundTripsCompactionKeyringAndUnknownMetadata(t *testing.T) {
	keyring, errKeyring := NewResponsesCompactionKeyring("account-a")
	if errKeyring != nil {
		t.Fatal(errKeyring)
	}
	path := filepath.Join(t.TempDir(), "codex.json")
	storage := &CodexTokenStorage{AccessToken: "access", AccountID: "account-a", ResponsesCompactionKeyring: keyring}
	storage.SetMetadata(map[string]any{"type": "codex", "account_id": "account-a", "prefix": "team"})
	if errSave := storage.SaveTokenToFile(path); errSave != nil {
		t.Fatal(errSave)
	}
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	var metadata map[string]any
	if errDecode := json.Unmarshal(raw, &metadata); errDecode != nil {
		t.Fatal(errDecode)
	}
	reloaded := NewTokenStorageFromMetadata(metadata)
	if reloaded.ResponsesCompactionKeyring == nil || reloaded.ResponsesCompactionKeyring.RootKey != keyring.RootKey {
		t.Fatal("persisted root did not survive token-storage reload")
	}
	if reloaded.Metadata["prefix"] != "team" {
		t.Fatal("unknown token metadata did not survive reload")
	}
	if _, exists := reloaded.Metadata[ResponsesCompactionKeyringMetadataKey]; exists {
		t.Fatal("reloaded token metadata exposed the root")
	}
	if got := metadata["access_token"]; got != "access" {
		t.Fatalf("saved access_token = %v, want access", got)
	}
}
