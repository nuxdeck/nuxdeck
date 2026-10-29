// SPDX-License-Identifier: AGPL-3.0-only

package audit

import (
	"strings"
	"testing"
)

func TestMaskDetails(t *testing.T) {
	in := `{"name":"web","token":"abc","nested":{"Password":"p","ok":1,"list":[{"totp_code":"123456"}]},"status_code":200,"code":"999","recovery_codes":["a"],"keep":"x"}`
	out := MaskDetails(in)
	for _, leak := range []string{"abc", `"p"`, "123456", "999", `["a"]`} {
		if strings.Contains(out, leak) {
			t.Errorf("%q leaked in %s", leak, out)
		}
	}
	for _, keep := range []string{`"name":"web"`, `"ok":1`, `"keep":"x"`} {
		if !strings.Contains(out, keep) {
			t.Errorf("%q lost in %s", keep, out)
		}
	}
	if got := MaskDetails("not json"); got != "{}" {
		t.Errorf("garbage = %q", got)
	}
}
