package executor

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

func makeTestCodexRefreshJWT(planType, accountID string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	authInfo := map[string]any{
		"chatgpt_account_id": accountID,
	}
	if planType != "" {
		authInfo["chatgpt_plan_type"] = planType
	}
	claimsMap := map[string]any{
		"email":                       "user@example.com",
		"https://api.openai.com/auth": authInfo,
	}
	payloadBytes, _ := json.Marshal(claimsMap)
	claims := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return header + "." + claims + "."
}

func startCodexMockOAuthServers(t *testing.T, idToken string) (proxyURL string, teardown func()) {
	t.Helper()

	mockAuthServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respBody := map[string]any{
			"access_token":  "new-mock-access-token",
			"refresh_token": "new-mock-refresh-token",
			"id_token":      idToken,
			"token_type":    "Bearer",
			"expires_in":    3600,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(respBody)
	}))

	mockProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			destConn, errDial := net.Dial("tcp", mockAuthServer.Listener.Addr().String())
			if errDial != nil {
				http.Error(w, errDial.Error(), http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				_ = destConn.Close()
				http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
				return
			}
			clientConn, _, errHijack := hijacker.Hijack()
			if errHijack != nil {
				_ = destConn.Close()
				return
			}
			go func() {
				defer func() { _ = destConn.Close() }()
				defer func() { _ = clientConn.Close() }()
				_, _ = io.Copy(destConn, clientConn)
			}()
			go func() {
				defer func() { _ = destConn.Close() }()
				defer func() { _ = clientConn.Close() }()
				_, _ = io.Copy(clientConn, destConn)
			}()
			return
		}
		http.Error(w, "proxy only supports CONNECT", http.StatusBadRequest)
	}))

	// Allow self-signed cert for the mock TLS server in HTTP transport
	origTransport := http.DefaultTransport
	http.DefaultTransport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	teardown = func() {
		http.DefaultTransport = origTransport
		mockProxy.Close()
		mockAuthServer.Close()
	}

	return mockProxy.URL, teardown
}

func TestCodexExecutorRefresh_MissingPlanTypeDefaultsToFree(t *testing.T) {
	idTokenWithoutPlan := makeTestCodexRefreshJWT("", "acc-codex-test")
	proxyURL, teardown := startCodexMockOAuthServers(t, idTokenWithoutPlan)
	defer teardown()

	cfg := &config.Config{}
	executor := NewCodexExecutor(cfg)

	storage := &codexauth.CodexTokenStorage{
		IDToken:      "old-id-token",
		AccessToken:  "old-access-token",
		RefreshToken: "old-refresh-token",
		PlanType:     "unknown",
	}

	auth := &cliproxyauth.Auth{
		ID:       "test-codex-refresh",
		Provider: "codex",
		Storage:  storage,
		ProxyURL: proxyURL,
		Metadata: map[string]any{
			"refresh_token": "valid-refresh-token",
		},
		Attributes: map[string]string{
			"plan_type": "unknown",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	refreshed, errRefresh := executor.Refresh(ctx, auth)
	if errRefresh != nil {
		t.Fatalf("executor.Refresh error = %v", errRefresh)
	}

	if got := refreshed.Attributes["plan_type"]; got != "free" {
		t.Errorf("refreshed.Attributes[plan_type] = %q, want free", got)
	}
	if got := refreshed.Metadata["plan_type"]; got != "free" {
		t.Errorf("refreshed.Metadata[plan_type] = %q, want free", got)
	}
	// Verify snapshot isolation: original storage remains unmodified
	if storage.PlanType != "unknown" {
		t.Errorf("original storage.PlanType mutated to %q, want unknown", storage.PlanType)
	}
	newStorage, ok := refreshed.Storage.(*codexauth.CodexTokenStorage)
	if !ok || newStorage == nil {
		t.Fatalf("refreshed.Storage is not *codexauth.CodexTokenStorage: %T", refreshed.Storage)
	}
	if newStorage.PlanType != "free" {
		t.Errorf("newStorage.PlanType = %q, want free", newStorage.PlanType)
	}

	// Verify persistence to credential file writes plan_type: free
	tempDir := t.TempDir()
	store := fileauth.NewFileTokenStore()
	store.SetBaseDir(tempDir)
	refreshed.Attributes[cliproxyauth.AttributePath] = filepath.Join(tempDir, "codex-refreshed.json")
	savedPath, errSave := store.Save(ctx, refreshed)
	if errSave != nil {
		t.Fatalf("store.Save error: %v", errSave)
	}
	savedBytes, errRead := os.ReadFile(savedPath)
	if errRead != nil {
		t.Fatalf("os.ReadFile error: %v", errRead)
	}
	var fileJSON map[string]any
	if errUnmarshal := json.Unmarshal(savedBytes, &fileJSON); errUnmarshal != nil {
		t.Fatalf("json.Unmarshal error: %v", errUnmarshal)
	}
	if got := fileJSON["plan_type"]; got != "free" {
		t.Errorf("credential file plan_type = %v, want free", got)
	}
}

func TestCodexExecutorRefresh_ExtractsPlanTypeWhenPresent(t *testing.T) {
	idTokenWithPlan := makeTestCodexRefreshJWT("team", "acc-codex-test-team")
	proxyURL, teardown := startCodexMockOAuthServers(t, idTokenWithPlan)
	defer teardown()

	cfg := &config.Config{}
	executor := NewCodexExecutor(cfg)

	storage := &codexauth.CodexTokenStorage{
		IDToken:      "old-id-token",
		AccessToken:  "old-access-token",
		RefreshToken: "old-refresh-token",
		PlanType:     "free",
	}

	auth := &cliproxyauth.Auth{
		ID:       "test-codex-refresh-team",
		Provider: "codex",
		Storage:  storage,
		ProxyURL: proxyURL,
		Metadata: map[string]any{
			"refresh_token": "valid-refresh-token-team",
		},
		Attributes: map[string]string{
			"plan_type": "free",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	refreshed, errRefresh := executor.Refresh(ctx, auth)
	if errRefresh != nil {
		t.Fatalf("executor.Refresh error = %v", errRefresh)
	}

	if got := refreshed.Attributes["plan_type"]; got != "team" {
		t.Errorf("refreshed.Attributes[plan_type] = %q, want team", got)
	}
	if got := refreshed.Metadata["plan_type"]; got != "team" {
		t.Errorf("refreshed.Metadata[plan_type] = %q, want team", got)
	}
	// Verify snapshot isolation: original storage remains unmodified
	if storage.PlanType != "free" {
		t.Errorf("original storage.PlanType mutated to %q, want free", storage.PlanType)
	}
	newStorage, ok := refreshed.Storage.(*codexauth.CodexTokenStorage)
	if !ok || newStorage == nil {
		t.Fatalf("refreshed.Storage is not *codexauth.CodexTokenStorage: %T", refreshed.Storage)
	}
	if newStorage.PlanType != "team" {
		t.Errorf("newStorage.PlanType = %q, want team", newStorage.PlanType)
	}

	// Verify persistence to credential file writes plan_type: team
	tempDir := t.TempDir()
	store := fileauth.NewFileTokenStore()
	store.SetBaseDir(tempDir)
	refreshed.Attributes[cliproxyauth.AttributePath] = filepath.Join(tempDir, "codex-team-refreshed.json")
	savedPath, errSave := store.Save(ctx, refreshed)
	if errSave != nil {
		t.Fatalf("store.Save error: %v", errSave)
	}
	savedBytes, errRead := os.ReadFile(savedPath)
	if errRead != nil {
		t.Fatalf("os.ReadFile error: %v", errRead)
	}
	var fileJSON map[string]any
	if errUnmarshal := json.Unmarshal(savedBytes, &fileJSON); errUnmarshal != nil {
		t.Fatalf("json.Unmarshal error: %v", errUnmarshal)
	}
	if got := fileJSON["plan_type"]; got != "team" {
		t.Errorf("credential file plan_type = %v, want team", got)
	}
}

func TestCodexExecutorRefreshPreservesOrRotatesCompactionRootByVerifiedAccount(t *testing.T) {
	for _, tc := range []struct {
		name          string
		refreshedAcct string
		preserve      bool
	}{
		{name: "same account rotation", refreshedAcct: "account-a", preserve: true},
		{name: "account replacement", refreshedAcct: "account-b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyring, errKeyring := codexauth.NewResponsesCompactionKeyring("account-a")
			if errKeyring != nil {
				t.Fatal(errKeyring)
			}
			idToken := makeTestCodexRefreshJWT("plus", tc.refreshedAcct)
			proxyURL, teardown := startCodexMockOAuthServers(t, idToken)
			defer teardown()
			originalStorage := &codexauth.CodexTokenStorage{
				IDToken:                    makeTestCodexRefreshJWT("plus", "account-a"),
				AccessToken:                "old-access-token",
				RefreshToken:               "old-refresh-token",
				AccountID:                  "account-a",
				ResponsesCompactionKeyring: keyring,
			}
			auth := &cliproxyauth.Auth{
				ID:       "codex-root-rotation",
				Provider: "codex",
				Storage:  originalStorage,
				ProxyURL: proxyURL,
				Metadata: map[string]any{
					"id_token":      originalStorage.IDToken,
					"access_token":  originalStorage.AccessToken,
					"refresh_token": originalStorage.RefreshToken,
					"account_id":    originalStorage.AccountID,
				},
			}
			executor := NewCodexExecutor(&config.Config{})
			oldScope, oldSecrets := executor.v1CompactionCredentials(auth)
			refreshed, errRefresh := executor.Refresh(context.Background(), auth)
			if errRefresh != nil {
				t.Fatal(errRefresh)
			}
			newStorage, ok := refreshed.Storage.(*codexauth.CodexTokenStorage)
			if !ok || newStorage.ResponsesCompactionKeyring == nil || !newStorage.ResponsesCompactionKeyring.ValidForAccount(tc.refreshedAcct) {
				t.Fatalf("refreshed auth has no valid root for %q: %#v", tc.refreshedAcct, refreshed.Storage)
			}
			if tc.preserve && newStorage.ResponsesCompactionKeyring.RootKey != keyring.RootKey {
				t.Fatal("same-account token rotation replaced the compaction root")
			}
			if !tc.preserve && newStorage.ResponsesCompactionKeyring.RootKey == keyring.RootKey {
				t.Fatal("account replacement retained the previous account root")
			}
			if _, exists := refreshed.Metadata[codexauth.ResponsesCompactionKeyringMetadataKey]; exists {
				t.Fatal("refreshed root was exposed in runtime metadata")
			}
			if originalStorage.ResponsesCompactionKeyring.RootKey != keyring.RootKey {
				t.Fatal("refresh mutated the prior storage snapshot")
			}
			newScope, newSecrets := executor.v1CompactionCredentials(refreshed)
			if tc.preserve && (oldScope != newScope || len(oldSecrets) != 1 || len(newSecrets) != 1 || oldSecrets[0] != newSecrets[0]) {
				t.Fatal("same-account access-token rotation changed the compaction binding")
			}
			if !tc.preserve && (oldScope == newScope && len(oldSecrets) == 1 && len(newSecrets) == 1 && oldSecrets[0] == newSecrets[0]) {
				t.Fatal("account replacement retained the previous compaction binding")
			}
		})
	}
}

func TestCodexExecutorRefreshInitializesAndPersistsMissingCompactionRoot(t *testing.T) {
	idToken := makeTestCodexRefreshJWT("plus", "account-a")
	proxyURL, teardown := startCodexMockOAuthServers(t, idToken)
	defer teardown()
	path := filepath.Join(t.TempDir(), "codex.json")
	auth := &cliproxyauth.Auth{
		ID:       "codex-legacy-account",
		Provider: "codex",
		ProxyURL: proxyURL,
		Metadata: map[string]any{
			"id_token":      makeTestCodexRefreshJWT("plus", "account-a"),
			"access_token":  "old-access-token",
			"refresh_token": "old-refresh-token",
			"account_id":    "account-a",
			"type":          "codex",
		},
		Attributes: map[string]string{cliproxyauth.AttributePath: path},
	}
	refreshed, errRefresh := NewCodexExecutor(&config.Config{}).Refresh(context.Background(), auth)
	if errRefresh != nil {
		t.Fatal(errRefresh)
	}
	storage, ok := refreshed.Storage.(*codexauth.CodexTokenStorage)
	if !ok || storage.ResponsesCompactionKeyring == nil || !storage.ResponsesCompactionKeyring.ValidForAccount("account-a") {
		t.Fatalf("successful authenticated refresh did not initialize the keyring: %#v", refreshed.Storage)
	}
	store := fileauth.NewFileTokenStore()
	savedPath, errSave := store.Save(context.Background(), refreshed)
	if errSave != nil {
		t.Fatal(errSave)
	}
	saved, errRead := os.ReadFile(savedPath)
	if errRead != nil {
		t.Fatal(errRead)
	}
	var persisted map[string]any
	if errDecode := json.Unmarshal(saved, &persisted); errDecode != nil {
		t.Fatal(errDecode)
	}
	persistedRoot, ok := codexauth.ResponsesCompactionKeyringFromValue(persisted[codexauth.ResponsesCompactionKeyringMetadataKey])
	if !ok || persistedRoot.RootKey != storage.ResponsesCompactionKeyring.RootKey {
		t.Fatal("authenticated refresh did not persist the new root")
	}
	if _, exists := refreshed.Metadata[codexauth.ResponsesCompactionKeyringMetadataKey]; exists {
		t.Fatal("persisted root remained in runtime metadata")
	}
}

func TestCodexHomeRefreshPreservesRootOnlyForSameVerifiedAuthEntry(t *testing.T) {
	for _, tc := range []struct {
		name          string
		previousAcct  string
		refreshedID   string
		refreshedAcct string
		preserve      bool
	}{
		{name: "same entry and account", previousAcct: "account-a", refreshedID: "codex-home-1", refreshedAcct: "account-a", preserve: true},
		{name: "account replacement", previousAcct: "account-a", refreshedID: "codex-home-1", refreshedAcct: "account-b"},
		{name: "different auth entry", previousAcct: "account-a", refreshedID: "codex-home-2", refreshedAcct: "account-a"},
		{name: "inconsistent previous account", previousAcct: "account-b", refreshedID: "codex-home-1", refreshedAcct: "account-a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyring, errKeyring := codexauth.NewResponsesCompactionKeyring("account-a")
			if errKeyring != nil {
				t.Fatal(errKeyring)
			}
			previousIDToken := makeTestCodexRefreshJWT("plus", tc.previousAcct)
			previous := &cliproxyauth.Auth{
				ID:       "codex-home-1",
				Provider: "codex",
				Storage: &codexauth.CodexTokenStorage{
					AccountID:                  "account-a",
					ResponsesCompactionKeyring: keyring,
				},
				Metadata: map[string]any{"id_token": previousIDToken, "account_id": "account-a"},
			}
			refreshed := &cliproxyauth.Auth{
				ID:       tc.refreshedID,
				Provider: "codex",
				Metadata: map[string]any{
					"id_token":      makeTestCodexRefreshJWT("plus", tc.refreshedAcct),
					"access_token":  "refreshed-access",
					"refresh_token": "refreshed-refresh",
					"account_id":    tc.refreshedAcct,
					codexauth.ResponsesCompactionKeyringMetadataKey: map[string]any{"version": 1, "account_id": "attacker", "root_key": keyring.RootKey},
				},
			}
			if errUpdate := updateCodexResponsesCompactionStorageFromHome(previous, refreshed); errUpdate != nil {
				t.Fatal(errUpdate)
			}
			storage, ok := refreshed.Storage.(*codexauth.CodexTokenStorage)
			if !ok || storage.ResponsesCompactionKeyring == nil || !storage.ResponsesCompactionKeyring.ValidForAccount(tc.refreshedAcct) {
				t.Fatalf("home refresh keyring is invalid for %q: %#v", tc.refreshedAcct, refreshed.Storage)
			}
			if tc.preserve && storage.ResponsesCompactionKeyring.RootKey != keyring.RootKey {
				t.Fatal("same account and auth entry lost the compaction root")
			}
			if !tc.preserve && storage.ResponsesCompactionKeyring.RootKey == keyring.RootKey {
				t.Fatal("account or auth entry replacement retained the prior root")
			}
			if _, exists := refreshed.Metadata[codexauth.ResponsesCompactionKeyringMetadataKey]; exists {
				t.Fatal("home refresh exposed the root in runtime metadata")
			}
		})
	}
}

func TestCodexOAuthCompactionFailsUntilVerifiedRootExists(t *testing.T) {
	executor := NewCodexExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		ID:       "codex-legacy-auth",
		Provider: "codex",
		Metadata: map[string]any{"access_token": "access", "account_id": "account-a"},
	}
	errCompaction := executor.v1CompactionCredentialError(auth, []byte(`{"input":[{"type":"compaction_trigger"}]}`))
	if errCompaction == nil || !strings.Contains(errCompaction.Error(), "successful authenticated refresh or re-login") {
		t.Fatalf("compaction guard error = %v, want clear refresh requirement", errCompaction)
	}
}

func TestCodexCompactionCapsuleSurvivesOAuthCredentialReload(t *testing.T) {
	keyring, errKeyring := codexauth.NewResponsesCompactionKeyring("account-a")
	if errKeyring != nil {
		t.Fatal(errKeyring)
	}
	idToken := makeTestCodexRefreshJWT("plus", "account-a")
	storage := &codexauth.CodexTokenStorage{
		IDToken:                    idToken,
		AccessToken:                "access-token",
		RefreshToken:               "refresh-token",
		AccountID:                  "account-a",
		ResponsesCompactionKeyring: keyring,
	}
	storage.SetMetadata(map[string]any{"email": "user@example.com", "account_id": "account-a"})
	auth := &cliproxyauth.Auth{
		ID:       "codex-restart-auth",
		Provider: "codex",
		Storage:  storage,
		Metadata: map[string]any{"id_token": idToken, "account_id": "account-a"},
	}
	executor := NewCodexExecutor(&config.Config{})
	scope, secrets := executor.v1CompactionCredentials(auth)
	response, errConvert := helps.ConvertResponsesCompactionResponse([]byte(`{"status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"continue after restart"}]}]}`), "gpt-5.4", scope, secrets)
	if errConvert != nil {
		t.Fatal(errConvert)
	}
	capsule := gjson.GetBytes(response, "output.1.encrypted_content").String()
	if capsule == "" {
		t.Fatalf("compaction response did not contain a capsule: %s", response)
	}
	credentialPath := filepath.Join(t.TempDir(), "codex.json")
	if errSave := storage.SaveTokenToFile(credentialPath); errSave != nil {
		t.Fatal(errSave)
	}
	persistedBytes, errRead := os.ReadFile(credentialPath)
	if errRead != nil {
		t.Fatal(errRead)
	}
	var persisted map[string]any
	if errDecode := json.Unmarshal(persistedBytes, &persisted); errDecode != nil {
		t.Fatal(errDecode)
	}
	reloadedStorage := codexauth.NewTokenStorageFromMetadata(persisted)
	reloadedAuth := &cliproxyauth.Auth{
		ID:       "codex-restart-auth",
		Provider: "codex",
		Storage:  reloadedStorage,
		Metadata: map[string]any{"id_token": reloadedStorage.IDToken, "account_id": reloadedStorage.AccountID},
	}
	reloadedScope, reloadedSecrets := executor.v1CompactionCredentials(reloadedAuth)
	request := []byte(`{"input":[{"type":"compaction","encrypted_content":"` + capsule + `"}]}`)
	expanded, errExpand := helps.ExpandResponsesCompactionCapsules(request, reloadedScope, reloadedSecrets)
	if errExpand != nil {
		t.Fatalf("capsule did not survive credential reload: %v", errExpand)
	}
	if !strings.Contains(string(expanded), "continue after restart") {
		t.Fatalf("reloaded capsule did not restore its summary: %s", expanded)
	}
	wrongEntry := *reloadedAuth
	wrongEntry.ID = "codex-replaced-auth"
	wrongScope, wrongSecrets := executor.v1CompactionCredentials(&wrongEntry)
	if _, errWrongScope := helps.ExpandResponsesCompactionCapsules(request, wrongScope, wrongSecrets); errWrongScope == nil {
		t.Fatal("capsule was accepted for a different auth entry")
	}
}

func TestCodexExecutorRefresh_EmptyAttributesSnapshotIsolation(t *testing.T) {
	idTokenWithoutPlan := makeTestCodexRefreshJWT("", "acc-codex-empty-attrs")
	proxyURL, teardown := startCodexMockOAuthServers(t, idTokenWithoutPlan)
	defer teardown()

	cfg := &config.Config{}
	executor := NewCodexExecutor(cfg)

	emptyAttrs := map[string]string{}
	storage := &codexauth.CodexTokenStorage{
		IDToken:      "old-id-token",
		AccessToken:  "old-access-token",
		RefreshToken: "old-refresh-token",
	}

	auth := &cliproxyauth.Auth{
		ID:         "test-codex-empty-attrs",
		Provider:   "codex",
		Storage:    storage,
		ProxyURL:   proxyURL,
		Attributes: emptyAttrs,
		Metadata: map[string]any{
			"refresh_token": "valid-refresh-token",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	refreshed, errRefresh := executor.Refresh(ctx, auth)
	if errRefresh != nil {
		t.Fatalf("executor.Refresh error = %v", errRefresh)
	}

	if got := refreshed.Attributes["plan_type"]; got != "free" {
		t.Errorf("refreshed.Attributes[plan_type] = %q, want free", got)
	}
	// Verify original empty map was not modified
	if _, exists := emptyAttrs["plan_type"]; exists {
		t.Errorf("original empty Attributes map was modified, plan_type = %q", emptyAttrs["plan_type"])
	}
	if len(emptyAttrs) != 0 {
		t.Errorf("original empty Attributes map length = %d, want 0", len(emptyAttrs))
	}
}
