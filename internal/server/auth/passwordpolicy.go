// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	_ "embed"
	"strings"
	"unicode/utf8"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// commonPasswords holds the 12-or-more character entries of the SecLists
// xato-net-10-million-passwords-1000000 list, lowercased (MIT, see REUSE.toml).
// Anything shorter is already rejected by the length rule.
//
//go:embed commonpasswords.txt
var commonPasswords string

const (
	minPasswordRunes = 12
	maxPasswordBytes = 256 // bounds hashing work; Argon2 input is not otherwise limited
)

// PasswordPolicy enforces ACC-1: at least 12 characters and not a known common or breached password.
type PasswordPolicy struct {
	common map[string]struct{}
}

// NewPasswordPolicy loads the embedded list.
func NewPasswordPolicy() *PasswordPolicy {
	lines := strings.Split(commonPasswords, "\n")
	set := make(map[string]struct{}, len(lines))
	for _, l := range lines {
		if l = strings.TrimSpace(l); l != "" {
			set[l] = struct{}{}
		}
	}
	return &PasswordPolicy{common: set}
}

// Check returns an AUTH-PWD-001 error naming the broken rule, or nil.
func (p *PasswordPolicy) Check(password, email string) error {
	switch {
	case utf8.RuneCountInString(password) < minPasswordRunes:
		return errcode.New(errcode.AuthPwd001, "use at least %d characters", minPasswordRunes)
	case len(password) > maxPasswordBytes:
		return errcode.New(errcode.AuthPwd001, "use at most %d bytes", maxPasswordBytes)
	}
	lower := strings.ToLower(password)
	if _, found := p.common[lower]; found {
		return errcode.New(errcode.AuthPwd001, "this password appears in lists of breached passwords; choose another")
	}
	if email != "" && (lower == strings.ToLower(email) || lower == strings.ToLower(strings.SplitN(email, "@", 2)[0])) {
		return errcode.New(errcode.AuthPwd001, "the password must not be your email address")
	}
	return nil
}
