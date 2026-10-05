package executor

import (
	"context"
	"strings"

	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

func (e *CodexExecutor) usesV1Compaction(auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) bool {
	var models []config.CodexModel
	prefix := ""
	if entry := e.resolveCodexConfig(auth); entry != nil {
		models = entry.Models
		prefix = entry.Prefix
	}
	return helps.ModelUsesV1Compaction(req, opts, models, prefix)
}

func (e *CodexExecutor) v1CompactionCredentials(auth *cliproxyauth.Auth) (string, []string) {
	if auth == nil {
		return "", nil
	}
	if auth.Attributes != nil && strings.TrimSpace(auth.Attributes["api_key"]) != "" {
		key := auth.Attributes["api_key"]
		baseURL := auth.Attributes["base_url"]
		if baseURL == "" {
			baseURL = "https://chatgpt.com/backend-api/codex"
		}
		return v1CompactionCredentialBinding(e.Identifier(), auth.ID, baseURL, key)
	}
	keyring, accountID := codexResponsesCompactionKeyring(auth)
	if keyring == nil {
		return "", nil
	}
	_, baseURL := codexCreds(auth)
	if baseURL == "" {
		baseURL = "https://chatgpt.com/backend-api/codex"
	}
	scope, secrets := v1CompactionCredentialBinding(e.Identifier(), auth.ID, baseURL, keyring.RootKey)
	if scope == "" {
		return "", nil
	}
	return strings.Join([]string{scope, "codex_account", accountID}, "\x00"), secrets
}

func codexResponsesCompactionKeyring(auth *cliproxyauth.Auth) (*codexauth.ResponsesCompactionKeyring, string) {
	if auth == nil {
		return nil, ""
	}
	metadataAccountID, _ := auth.Metadata["account_id"].(string)
	var storageAccountID string
	var keyring *codexauth.ResponsesCompactionKeyring
	if storage, ok := auth.Storage.(*codexauth.CodexTokenStorage); ok && storage != nil {
		storageAccountID = storage.AccountID
		keyring = storage.ResponsesCompactionKeyring
	}
	if keyring == nil {
		keyring, _ = codexauth.ResponsesCompactionKeyringFromValue(auth.Metadata[codexauth.ResponsesCompactionKeyringMetadataKey])
	}
	metadataAccountID = strings.TrimSpace(metadataAccountID)
	storageAccountID = strings.TrimSpace(storageAccountID)
	if metadataAccountID != "" && storageAccountID != "" && metadataAccountID != storageAccountID {
		return nil, metadataAccountID
	}
	accountID := metadataAccountID
	if accountID == "" {
		accountID = storageAccountID
	}
	if keyring == nil || !keyring.ValidForAccount(accountID) {
		return nil, accountID
	}
	return keyring, accountID
}

func (e *CodexExecutor) v1CompactionCredentialError(auth *cliproxyauth.Auth, payload []byte) error {
	if !helps.HasResponsesCompactionTrigger(payload) && !hasCodexResponsesCompactionCapsule(payload) {
		return nil
	}
	if auth != nil && auth.Attributes != nil && strings.TrimSpace(auth.Attributes["api_key"]) != "" {
		return nil
	}
	if keyring, _ := codexResponsesCompactionKeyring(auth); keyring != nil {
		return nil
	}
	return helps.ResponsesCompactionError{Message: "Codex OAuth compaction requires a successful authenticated refresh or re-login to initialize an account-bound keyring"}
}

func hasCodexResponsesCompactionCapsule(payload []byte) bool {
	for _, item := range gjson.GetBytes(payload, "input").Array() {
		if item.Get("type").String() == "compaction" && strings.HasPrefix(item.Get("encrypted_content").String(), "cpa-responses-v1-compaction-") {
			return true
		}
	}
	return false
}

func (e *CodexExecutor) prepareV1Compaction(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Request, bool, error) {
	if opts.Alt != "" || !e.usesV1Compaction(auth, req, opts) || (opts.SourceFormat != sdktranslator.FormatOpenAIResponse && opts.SourceFormat != sdktranslator.FormatCodex) {
		return req, false, nil
	}
	summary := helps.HasResponsesCompactionTrigger(req.Payload)
	if err := e.v1CompactionCredentialError(auth, req.Payload); err != nil {
		return req, false, err
	}
	if summary || helps.HasResponsesCompactionItem(req.Payload) {
		if err := helps.ValidateV1CompactionContext(ctx, req.Payload); err != nil {
			return req, false, err
		}
	}
	scope, secrets := e.v1CompactionCredentials(auth)
	payload, errExpand := helps.ExpandResponsesCompactionCapsules(req.Payload, scope, secrets)
	if errExpand == nil {
		req.Payload = payload
	}
	return req, summary && errExpand == nil, errExpand
}

func (e *OpenAICompatExecutor) usesV1Compaction(auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) bool {
	var models []config.OpenAICompatibilityModel
	prefix := ""
	if entry := e.resolveCompatConfig(auth, req); entry != nil {
		models = entry.Models
		prefix = entry.Prefix
	}
	return helps.ModelUsesV1Compaction(req, opts, models, prefix)
}

func (e *OpenAICompatExecutor) v1CompactionCredentials(auth *cliproxyauth.Auth, req cliproxyexecutor.Request) (string, []string) {
	if auth == nil {
		return "", nil
	}
	baseURL, key := e.resolveCredentials(auth)
	return v1CompactionCredentialBinding(e.Identifier(), auth.ID, baseURL, key)
}

func v1CompactionCredentialBinding(executorID, authID, baseURL, credential string) (string, []string) {
	executorID = strings.TrimSpace(executorID)
	authID = strings.TrimSpace(authID)
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	credential = strings.TrimSpace(credential)
	if executorID == "" || authID == "" || baseURL == "" || credential == "" {
		return "", nil
	}
	return strings.Join([]string{executorID, authID, baseURL}, "\x00"), []string{credential}
}

func (e *OpenAICompatExecutor) needsV1Responses(auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) bool {
	return opts.Alt == "" && (opts.SourceFormat == sdktranslator.FormatOpenAIResponse || opts.SourceFormat == sdktranslator.FormatCodex) && e.usesV1Compaction(auth, req, opts) && (helps.HasResponsesCompactionTrigger(req.Payload) || helps.HasResponsesCompactionItem(req.Payload))
}
