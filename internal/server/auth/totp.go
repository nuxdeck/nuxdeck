// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 default; authenticator apps do not reliably support more
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	totpPeriod     = 30
	totpDigits     = 6
	totpSecretLen  = 20
	totpWindowStep = 1
)

var totpBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns 160 random bits, the size RFC 4226 recommends.
func NewTOTPSecret() ([]byte, error) {
	b := make([]byte, totpSecretLen)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate TOTP secret: %w", err)
	}
	return b, nil
}

// EncodeTOTPSecret renders a secret the way authenticator apps accept it.
func EncodeTOTPSecret(secret []byte) string { return totpBase32.EncodeToString(secret) }

// OTPAuthURI is the otpauth:// URI that authenticator apps scan or accept pasted.
func OTPAuthURI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", EncodeTOTPSecret(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// TOTPStep is the RFC 6238 time step containing t.
func TOTPStep(t time.Time) int64 { return t.Unix() / totpPeriod }

// totpCode is HOTP (RFC 4226) over the step counter.
func totpCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) //nolint:gosec // step is a positive time counter
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, v%1_000_000)
}

// VerifyTOTP accepts code for the steps within one period of now, but only a
// step newer than lastStep: a code is good once (replay protection). All
// candidate steps are compared, in constant time, before deciding.
func VerifyTOTP(secret []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0, false
	}
	cur := TOTPStep(now)
	var matched int64
	for d := int64(-totpWindowStep); d <= totpWindowStep; d++ {
		step := cur + d
		if subtle.ConstantTimeCompare([]byte(code), []byte(totpCode(secret, step))) == 1 && step > lastStep && step > matched {
			matched = step
		}
	}
	return matched, matched != 0
}

// TOTPEnrolment is what the user needs to add the account to an authenticator app.
type TOTPEnrolment struct {
	Secret string
	URI    string
}

// TOTPCodeAt returns the code an authenticator shows at t. Tests and tools use it; verification goes through VerifyTOTP.
func TOTPCodeAt(secret []byte, t time.Time) string { return totpCode(secret, TOTPStep(t)) }
