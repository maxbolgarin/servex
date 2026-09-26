package servex

import (
	"crypto/subtle"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Two guards on second-factor codes, both per USER rather than per pending token.
//
// Attempts were counted per 2FA pending token only, and every password login mints a new one, so a
// caller who knew the password got a fresh budget of guesses per login. And a correct TOTP code was
// accepted as many times as it was presented within its window, so a code seen once (over a
// shoulder, in a proxy log, from a phishing page) signed in a second time.

// totpPeriod is the TOTP time step. Codes are generated with the pquerna/otp defaults (30s,
// 6 digits, SHA1), and totp.Validate accepts one step either side of now.
const totpPeriod = 30 * time.Second

// userFailLimitFactor sets the per-user failure limit as a multiple of MaxVerifyAttempts, so one
// pending token still runs out first and a user who mistypes a few times is not locked out.
const userFailLimitFactor = 3

func userFailKey(userID string) string { return "user-fail:" + userID }
func userTOTPKey(userID string) string { return "user-totp:" + userID }

// totpStep returns the time step (Unix seconds / 30) the code is valid for, within one step either
// side of now: the same window totp.Validate accepts.
func totpStep(code, secret string, now time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	opts := totp.ValidateOpts{Period: uint(totpPeriod / time.Second), Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
	for _, skew := range []time.Duration{0, -totpPeriod, totpPeriod} {
		at := now.Add(skew)
		want, err := totp.GenerateCodeCustom(secret, at, opts)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return at.Unix() / int64(totpPeriod/time.Second), true
		}
	}
	return 0, false
}

// userLocked reports whether the user has used up their failures across all pending tokens.
func (h *AuthManager) userLocked(userID string) bool {
	return h.attemptTracker.getCount(userFailKey(userID)) >= userFailLimitFactor*h.service.cfg.TwoFactor.MaxVerifyAttempts
}

// acceptTOTPStep records a step as used by the user and reports whether it was new. A code for a
// step already accepted, or an earlier one, is a replay. Kept in memory, per process.
func (t *attemptTracker) acceptTOTPStep(userID string, step int64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	entry := t.getOrCreate(userTOTPKey(userID))
	if step <= entry.lastTOTPStep {
		return false
	}
	entry.lastTOTPStep = step
	// Well past the window in which the step's code can be presented again.
	entry.expiresAt = time.Now().Add(t.maxAge)
	return true
}

// checkTOTPOnce validates a TOTP code and consumes its time step. replayed is true for a correct
// code whose step the user already used; the caller must treat that as a failed attempt.
func (h *AuthManager) checkTOTPOnce(userID, code, secret string) (valid, replayed bool) {
	step, ok := totpStep(code, secret, time.Now())
	if !ok {
		return false, false
	}
	if !h.attemptTracker.acceptTOTPStep(userID, step) {
		return false, true
	}
	return true, false
}
