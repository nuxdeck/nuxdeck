// SPDX-License-Identifier: Apache-2.0

package logs

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// unitPattern admits the characters of a systemd unit name, minus the backslash escape and
// glob characters, and insists on a leading alphanumeric so the value can never read as an
// option. Together with exec without a shell this closes argument and command injection.
var unitPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.@-]{0,254}$`)

// ValidateUnit checks a unit name from the server before it reaches journalctl's arguments.
func ValidateUnit(unit string) error {
	if !unitPattern.MatchString(unit) {
		return errors.New("not a valid systemd unit name")
	}
	return nil
}

const (
	maxJournalEntry = 64 << 10
	killGrace       = 2 * time.Second
)

// journalctlPaths are tried in order; a PATH lookup is avoided so the agent runs only the
// system's own binary.
var journalctlPaths = []string{"/usr/bin/journalctl", "/bin/journalctl"}

func findJournalctl(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	for _, p := range journalctlPaths {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return p, nil
		}
	}
	return "", errcode.New(errcode.LOGSrc002, "journalctl not found")
}

// journalArgs builds the fixed argument list. The unit sits in its own element after -u and
// has been validated, so it cannot become an option or a second argument.
func journalArgs(unit string, tail uint32, sinceMs int64) []string {
	args := []string{"--no-pager", "--output=json", "--follow", "--unit=" + unit}
	if sinceMs > 0 {
		return append(args, "--since=@"+strconv.FormatInt(sinceMs/1000, 10), "--lines=all")
	}
	return append(args, "--lines="+strconv.FormatUint(uint64(tail), 10))
}

// streamJournal follows a unit's journal until the context ends or journalctl exits. The
// process is killed when the context is cancelled and runs with an empty environment.
func streamJournal(ctx context.Context, override, unit string, tail uint32, sinceMs int64, s *sink) error {
	path, err := findJournalctl(override)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, path, journalArgs(unit, tail, sinceMs)...) //nolint:gosec // fixed binary, validated unit, no shell
	cmd.Env = []string{"LC_ALL=C.UTF-8"}
	cmd.WaitDelay = killGrace
	out, err := cmd.StdoutPipe()
	if err != nil {
		return errcode.Wrap(errcode.LOGSrc002, "journalctl pipe", err)
	}
	if err := cmd.Start(); err != nil {
		return errcode.Wrap(errcode.LOGSrc002, "start journalctl", err)
	}

	rerr := readJournal(out, s)
	_ = out.Close()
	if ctx.Err() != nil {
		_ = cmd.Wait()
		return nil
	}
	if werr := cmd.Wait(); werr != nil {
		return errcode.Wrap(errcode.LOGSrc002, "journalctl exited", werr)
	}
	if !errors.Is(rerr, io.EOF) { // readJournal returns only when the stream ends
		return errcode.Wrap(errcode.LOGSrc002, "read journal", rerr)
	}
	return nil
}

// readJournal turns journalctl's one-JSON-object-per-line output into log lines.
func readJournal(r io.Reader, s *sink) error {
	br := bufio.NewReaderSize(r, 32<<10)
	for {
		raw, tooLong, err := readBounded(br, maxJournalEntry)
		if len(raw) > 0 || tooLong {
			ts, text := parseJournalEntry(raw, tooLong)
			if aerr := s.add(ts, agentv1.LogLine_SOURCE_JOURNAL, text); aerr != nil {
				return aerr
			}
		}
		if err != nil {
			return err
		}
	}
}

// readBounded reads one line of at most limit bytes and discards the excess.
func readBounded(br *bufio.Reader, limit int) (line []byte, tooLong bool, err error) {
	for {
		frag, ferr := br.ReadSlice('\n')
		if room := limit - len(line); len(frag) > room {
			frag, tooLong = frag[:room], true
		}
		line = append(line, frag...)
		if errors.Is(ferr, bufio.ErrBufferFull) {
			continue
		}
		if n := len(line); n > 0 && line[n-1] == '\n' {
			line = line[:n-1]
		}
		return line, tooLong, ferr
	}
}

// parseJournalEntry extracts the message and time. MESSAGE is a string, or an array of byte
// values when it is not valid UTF-8.
func parseJournalEntry(raw []byte, tooLong bool) (time.Time, []byte) {
	if tooLong {
		return time.Now(), []byte("[journal entry too large to show]")
	}
	var e struct {
		Message   json.RawMessage `json:"MESSAGE"`
		Timestamp string          `json:"__REALTIME_TIMESTAMP"`
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		return time.Now(), []byte("[unreadable journal entry]")
	}
	ts := time.Now()
	if us, err := strconv.ParseInt(e.Timestamp, 10, 64); err == nil {
		ts = time.UnixMicro(us)
	}
	var text string
	if err := json.Unmarshal(e.Message, &text); err == nil {
		return ts, []byte(text)
	}
	var b []byte
	var nums []int
	if err := json.Unmarshal(e.Message, &nums); err == nil {
		for _, n := range nums {
			b = append(b, byte(n)) //nolint:gosec // journald encodes bytes as 0..255
		}
		return ts, b
	}
	return ts, nil
}
