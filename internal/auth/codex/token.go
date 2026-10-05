// Package codex provides authentication and token management functionality
// for OpenAI's Codex AI services. It handles OAuth2 token storage, serialization,
// and retrieval for maintaining authenticated sessions with the Codex API.
package codex

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/misc"
	log "github.com/sirupsen/logrus"
)

// ResponsesCompactionKeyringMetadataKey is the reserved credential-file key used to hydrate the typed keyring.
const ResponsesCompactionKeyringMetadataKey = "codex_responses_compaction_keyring"

const responsesCompactionKeyringVersion = 1

// ResponsesCompactionKeyring holds a stable random root bound to one verified Codex account.
type ResponsesCompactionKeyring struct {
	Version   int    `json:"version"`
	AccountID string `json:"account_id"`
	RootKey   string `json:"root_key"`
}

// NewResponsesCompactionKeyring creates a random keyring for a verified account ID.
func NewResponsesCompactionKeyring(accountID string) (*ResponsesCompactionKeyring, error) {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return nil, fmt.Errorf("codex compaction keyring requires a verified account ID")
	}
	root := make([]byte, 32)
	if _, err := rand.Read(root); err != nil {
		return nil, fmt.Errorf("codex compaction keyring generation failed: %w", err)
	}
	return &ResponsesCompactionKeyring{Version: responsesCompactionKeyringVersion, AccountID: accountID, RootKey: base64.RawURLEncoding.EncodeToString(root)}, nil
}

// ValidForAccount reports whether the keyring has a supported version and a valid root for accountID.
func (k *ResponsesCompactionKeyring) ValidForAccount(accountID string) bool {
	if k == nil || k.Version != responsesCompactionKeyringVersion || strings.TrimSpace(accountID) == "" || k.AccountID != strings.TrimSpace(accountID) {
		return false
	}
	root, err := base64.RawURLEncoding.DecodeString(k.RootKey)
	return err == nil && len(root) == 32
}

// ResponsesCompactionKeyringFromValue parses a persisted keyring without trusting its account binding.
func ResponsesCompactionKeyringFromValue(value any) (*ResponsesCompactionKeyring, bool) {
	if value == nil {
		return nil, false
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, false
	}
	var keyring ResponsesCompactionKeyring
	if err := json.Unmarshal(encoded, &keyring); err != nil || keyring.Version != responsesCompactionKeyringVersion || !keyring.ValidForAccount(keyring.AccountID) {
		return nil, false
	}
	return &keyring, true
}

// CodexTokenStorage stores OAuth2 token information for OpenAI Codex API authentication.
// It maintains compatibility with the existing auth system while adding Codex-specific fields
// for managing access tokens, refresh tokens, and user account information.
type CodexTokenStorage struct {
	// IDToken is the JWT ID token containing user claims and identity information.
	IDToken string `json:"id_token"`
	// AccessToken is the OAuth2 access token used for authenticating API requests.
	AccessToken string `json:"access_token"`
	// RefreshToken is used to obtain new access tokens when the current one expires.
	RefreshToken string `json:"refresh_token"`
	// AccountID is the OpenAI account identifier associated with this token.
	AccountID string `json:"account_id"`
	// LastRefresh is the timestamp of the last token refresh operation.
	LastRefresh string `json:"last_refresh"`
	// Email is the OpenAI account email address associated with this token.
	Email string `json:"email"`
	// Type indicates the authentication provider type, always "codex" for this storage.
	Type string `json:"type"`
	// Expire is the timestamp when the current access token expires.
	Expire string `json:"expired"`
	// PlanType indicates the ChatGPT subscription plan type, defaults to "free" if not present.
	PlanType string `json:"plan_type,omitempty"`
	// ResponsesCompactionKeyring stores the stable per-account root for native Responses capsules.
	ResponsesCompactionKeyring *ResponsesCompactionKeyring `json:"codex_responses_compaction_keyring,omitempty"`

	// Metadata holds arbitrary key-value pairs injected via hooks.
	// It is not exported to JSON directly to allow flattening during serialization.
	Metadata map[string]any `json:"-"`
}

// SetMetadata allows external callers to inject metadata into the storage before saving.
func (ts *CodexTokenStorage) SetMetadata(meta map[string]any) {
	if ts == nil {
		return
	}
	metadata := maps.Clone(meta)
	if ts.ResponsesCompactionKeyring != nil && !ts.ResponsesCompactionKeyring.ValidForAccount(ts.AccountID) {
		ts.ResponsesCompactionKeyring = nil
	}
	if raw, exists := metadata[ResponsesCompactionKeyringMetadataKey]; exists {
		if keyring, ok := ResponsesCompactionKeyringFromValue(raw); ok && keyring.ValidForAccount(ts.AccountID) && ts.ResponsesCompactionKeyring == nil {
			ts.ResponsesCompactionKeyring = keyring
		}
		delete(metadata, ResponsesCompactionKeyringMetadataKey)
		delete(meta, ResponsesCompactionKeyringMetadataKey)
	}
	ts.Metadata = metadata
}

// NewTokenStorageFromMetadata builds token storage from a flattened Codex credential file.
func NewTokenStorageFromMetadata(metadata map[string]any) *CodexTokenStorage {
	storage := &CodexTokenStorage{
		IDToken:      metadataString(metadata, "id_token"),
		AccessToken:  metadataString(metadata, "access_token"),
		RefreshToken: metadataString(metadata, "refresh_token"),
		AccountID:    metadataString(metadata, "account_id"),
		LastRefresh:  metadataString(metadata, "last_refresh"),
		Email:        metadataString(metadata, "email"),
		Type:         metadataString(metadata, "type"),
		Expire:       metadataString(metadata, "expired"),
		PlanType:     metadataString(metadata, "plan_type"),
	}
	if keyring, ok := ResponsesCompactionKeyringFromValue(metadata[ResponsesCompactionKeyringMetadataKey]); ok && keyring.ValidForAccount(storage.AccountID) {
		storage.ResponsesCompactionKeyring = keyring
	}
	storage.SetMetadata(metadata)
	return storage
}

func metadataString(metadata map[string]any, key string) string {
	value, _ := metadata[key].(string)
	return value
}

// SaveTokenToFile serializes the Codex token storage to a JSON file.
// This method creates the necessary directory structure and writes the token
// data in JSON format to the specified file path for persistent storage.
// It merges any injected metadata into the top-level JSON object.
//
// Parameters:
//   - authFilePath: The full path where the token file should be saved
//
// Returns:
//   - error: An error if the operation fails, nil otherwise
func (ts *CodexTokenStorage) SaveTokenToFile(authFilePath string) error {
	misc.LogSavingCredentials(authFilePath)
	ts.Type = "codex"
	if err := os.MkdirAll(filepath.Dir(authFilePath), 0700); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// Merge metadata using helper
	data, errMerge := misc.MergeMetadata(ts, ts.Metadata)
	if errMerge != nil {
		return fmt.Errorf("failed to merge metadata: %w", errMerge)
	}

	f, err := os.Create(authFilePath)
	if err != nil {
		return fmt.Errorf("failed to create token file: %w", err)
	}
	defer func() {
		if errClose := f.Close(); errClose != nil {
			log.Errorf("codex token storage: close token file error: %v", errClose)
		}
	}()

	if err = json.NewEncoder(f).Encode(data); err != nil {
		return fmt.Errorf("failed to write token to file: %w", err)
	}
	return nil
}
