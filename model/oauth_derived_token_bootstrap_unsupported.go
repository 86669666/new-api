//go:build !linux

package model

import (
	"context"
	"fmt"
	"io"
)

// Provisioning authority is implemented only for Linux. Ordinary unanchored
// gateway startup stays portable; no other platform may create or trust a seal.
func oauthProtectedPath(string, bool) error                          { return errOAuthBootstrap }
func readOAuthBirthJournal(string, bool) (*oauthBirthJournal, error) { return nil, errOAuthBootstrap }
func oauthSQLiteBinding(string) (string, error)                      { return "", errOAuthBootstrap }
func oauthSocketEndpoint(string) (string, error)                     { return "", errOAuthBootstrap }
func oauthBootstrap(_ context.Context, _, _, _, _ string, out io.Writer) error {
	fmt.Fprintln(out, "db-bootstrap unsupported on this platform; Linux provisioning is required")
	return errOAuthBootstrap
}
