package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
)

func makeTestCodexJWT(planType, accountID string) string {
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

func TestBuildAuthRecord_PlanTypeDefaultsToFreeWhenMissing(t *testing.T) {
	authenticator := NewCodexAuthenticator()
	authSvc := codex.NewCodexAuth(nil)

	idTokenWithoutPlan := makeTestCodexJWT("", "acc-12345")
	bundle := &codex.CodexAuthBundle{
		TokenData: codex.CodexTokenData{
			IDToken:      idTokenWithoutPlan,
			AccessToken:  "mock-access-token",
			RefreshToken: "mock-refresh-token",
			Email:        "user@example.com",
		},
	}

	auth, errBuild := authenticator.buildAuthRecord(authSvc, bundle)
	if errBuild != nil {
		t.Fatalf("buildAuthRecord error: %v", errBuild)
	}

	if got := auth.Attributes["plan_type"]; got != "free" {
		t.Errorf("auth.Attributes[plan_type] = %q, want free", got)
	}
	if got := auth.Metadata["plan_type"]; got != "free" {
		t.Errorf("auth.Metadata[plan_type] = %q, want free", got)
	}
	storage, ok := auth.Storage.(*codex.CodexTokenStorage)
	if !ok || storage == nil {
		t.Fatalf("auth.Storage is not *codex.CodexTokenStorage: %T", auth.Storage)
	}
	if storage.PlanType != "free" {
		t.Errorf("storage.PlanType = %q, want free", storage.PlanType)
	}
	if storage.ResponsesCompactionKeyring == nil || !storage.ResponsesCompactionKeyring.ValidForAccount("acc-12345") {
		t.Fatal("successful OAuth login did not create a verified-account compaction root")
	}
	if !strings.HasSuffix(auth.FileName, "-free.json") {
		t.Errorf("auth.FileName = %q, want suffix -free.json", auth.FileName)
	}
}

func TestBuildAuthRecord_PlanTypeExtractedWhenPresent(t *testing.T) {
	authenticator := NewCodexAuthenticator()
	authSvc := codex.NewCodexAuth(nil)

	idTokenWithPlan := makeTestCodexJWT("plus", "acc-12345")
	bundle := &codex.CodexAuthBundle{
		TokenData: codex.CodexTokenData{
			IDToken:      idTokenWithPlan,
			AccessToken:  "mock-access-token",
			RefreshToken: "mock-refresh-token",
			Email:        "user@example.com",
			PlanType:     "plus",
		},
	}

	auth, errBuild := authenticator.buildAuthRecord(authSvc, bundle)
	if errBuild != nil {
		t.Fatalf("buildAuthRecord error: %v", errBuild)
	}

	if got := auth.Attributes["plan_type"]; got != "plus" {
		t.Errorf("auth.Attributes[plan_type] = %q, want plus", got)
	}
	if got := auth.Metadata["plan_type"]; got != "plus" {
		t.Errorf("auth.Metadata[plan_type] = %q, want plus", got)
	}
	storage, ok := auth.Storage.(*codex.CodexTokenStorage)
	if !ok || storage == nil {
		t.Fatalf("auth.Storage is not *codex.CodexTokenStorage: %T", auth.Storage)
	}
	if storage.PlanType != "plus" {
		t.Errorf("storage.PlanType = %q, want plus", storage.PlanType)
	}
	if !strings.HasSuffix(auth.FileName, "-plus.json") {
		t.Errorf("auth.FileName = %q, want suffix -plus.json", auth.FileName)
	}
}

func TestBuildAuthRecordWithoutAccountClaimKeepsOAuthLoginAvailable(t *testing.T) {
	authenticator := NewCodexAuthenticator()
	authSvc := codex.NewCodexAuth(nil)
	bundle := &codex.CodexAuthBundle{TokenData: codex.CodexTokenData{
		IDToken:      makeTestCodexJWT("plus", ""),
		AccessToken:  "mock-access-token",
		RefreshToken: "mock-refresh-token",
		Email:        "user@example.com",
	}}
	authRecord, errBuild := authenticator.buildAuthRecord(authSvc, bundle)
	if errBuild != nil {
		t.Fatalf("buildAuthRecord error: %v", errBuild)
	}
	storage, ok := authRecord.Storage.(*codex.CodexTokenStorage)
	if !ok || storage == nil {
		t.Fatalf("auth storage = %T, want *codex.CodexTokenStorage", authRecord.Storage)
	}
	if storage.ResponsesCompactionKeyring != nil {
		t.Fatal("login without a verified account created a compaction root")
	}
	if authRecord.Metadata["account_id"] != nil {
		t.Fatal("login without a verified account published an account ID")
	}
}

func TestBuildAuthRecordCreatesFreshAccountBoundCompactionRoot(t *testing.T) {
	authenticator := NewCodexAuthenticator()
	authSvc := codex.NewCodexAuth(nil)
	bundle := &codex.CodexAuthBundle{TokenData: codex.CodexTokenData{
		IDToken:     makeTestCodexJWT("plus", "account-a"),
		AccessToken: "mock-access-token",
		Email:       "user@example.com",
	}}
	first, errFirst := authenticator.buildAuthRecord(authSvc, bundle)
	if errFirst != nil {
		t.Fatal(errFirst)
	}
	second, errSecond := authenticator.buildAuthRecord(authSvc, bundle)
	if errSecond != nil {
		t.Fatal(errSecond)
	}
	firstStorage := first.Storage.(*codex.CodexTokenStorage)
	secondStorage := second.Storage.(*codex.CodexTokenStorage)
	if firstStorage.AccountID != "account-a" || !firstStorage.ResponsesCompactionKeyring.ValidForAccount("account-a") {
		t.Fatal("login did not create an account-bound compaction root")
	}
	if firstStorage.ResponsesCompactionKeyring.RootKey == secondStorage.ResponsesCompactionKeyring.RootKey {
		t.Fatal("separate login records reused the same compaction root")
	}
	if _, exists := first.Metadata[codex.ResponsesCompactionKeyringMetadataKey]; exists {
		t.Fatal("compaction root was exposed in runtime auth metadata")
	}
	serialized, errMarshal := json.Marshal(first)
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	if strings.Contains(string(serialized), firstStorage.ResponsesCompactionKeyring.RootKey) {
		t.Fatal("serialized auth reply exposed its storage-only compaction root")
	}
}
