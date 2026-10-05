package store

import (
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func hydrateCodexTokenStorage(auth *cliproxyauth.Auth) {
	if auth == nil || !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") || auth.Metadata == nil {
		return
	}
	if _, exists := auth.Metadata[codex.ResponsesCompactionKeyringMetadataKey]; !exists {
		return
	}
	auth.Storage = codex.NewTokenStorageFromMetadata(auth.Metadata)
}
