// SPDX-License-Identifier: Apache-2.0

package logs

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	agentv1 "github.com/nuxdeck/nuxdeck/proto/nuxdeck/agent/v1"
)

// containerIDPattern is the ID shape nux-sockguard accepts.
var containerIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

const (
	inspectLimit = 2 << 20 // sockguard caps inspect answers at 2 MB
	// maxFrame bounds one multiplexed frame; the runtime's frames are far smaller.
	maxFrame = 8 << 20
)

// dockerClient speaks the Docker-compatible API, but only to nux-sockguard's socket (ADR-011).
type dockerClient struct{ http *http.Client }

func newDockerClient(socket string) *dockerClient {
	return &dockerClient{http: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
		},
		DisableCompression:    true,
		MaxIdleConns:          2,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
	}}}
}

func (c *dockerClient) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://sockguard"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, errcode.Wrap(errcode.LOGSrc001, "reach nux-sockguard", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, errcode.New(errcode.LOGSrc001, "GET logs: HTTP %d", resp.StatusCode)
	}
	return resp, nil
}

// isTTY reports whether the container has a terminal; its log stream is then raw, not framed.
func (c *dockerClient) isTTY(ctx context.Context, id string) (bool, error) {
	resp, err := c.get(ctx, "/containers/"+url.PathEscape(id)+"/json")
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	var v struct{ Config struct{ Tty bool } }
	if err := json.NewDecoder(io.LimitReader(resp.Body, inspectLimit)).Decode(&v); err != nil {
		return false, errcode.Wrap(errcode.LOGSrc001, "decode container", err)
	}
	return v.Config.Tty, nil
}

// stream follows a container's logs until the context ends or the container's stream closes.
func (c *dockerClient) stream(ctx context.Context, id string, tail uint32, sinceMs int64, s *sink) error {
	tty, err := c.isTTY(ctx, id)
	if err != nil {
		return err
	}
	q := url.Values{"follow": {"1"}, "stdout": {"1"}, "stderr": {"1"}, "timestamps": {"1"}, "tail": {strconv.FormatUint(uint64(tail), 10)}}
	if sinceMs > 0 {
		q.Set("since", fmt.Sprintf("%d.%03d", sinceMs/1000, sinceMs%1000))
	}
	resp, err := c.get(ctx, "/containers/"+url.PathEscape(id)+"/logs?"+q.Encode())
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	var rerr error
	if tty {
		rerr = readRaw(resp.Body, s)
	} else {
		rerr = demux(resp.Body, s)
	}
	if ctx.Err() != nil || errors.Is(rerr, io.EOF) {
		return nil
	}
	return errcode.Wrap(errcode.LOGSrc001, "read container logs", rerr)
}

// readRaw reads a TTY stream, where stdout and stderr are merged and there is no framing.
func readRaw(r io.Reader, s *sink) error {
	a := newAssembler(s, agentv1.LogLine_SOURCE_STDOUT)
	return a.copyFrom(r, -1)
}

// demux reads Docker's multiplexed stream: frames of an 8-byte header (stream type, three
// zero bytes, big-endian payload size) and the payload. Each stream keeps its own partial
// line, because a frame may end mid-line and stdout and stderr interleave.
func demux(r io.Reader, s *sink) error {
	br := bufio.NewReaderSize(r, 32<<10)
	out := newAssembler(s, agentv1.LogLine_SOURCE_STDOUT)
	errA := newAssembler(s, agentv1.LogLine_SOURCE_STDERR)
	var hdr [8]byte
	for {
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return io.EOF // a cut-off header: the container went away mid-write
			}
			return err
		}
		size := int64(binary.BigEndian.Uint32(hdr[4:]))
		if hdr[1] != 0 || hdr[2] != 0 || hdr[3] != 0 || size > maxFrame {
			return errors.New("malformed log frame")
		}
		a := out
		switch hdr[0] {
		case 0, 1: // stdin is never expected; treat as stdout
		case 2:
			a = errA
		default:
			return fmt.Errorf("unknown log stream type %d", hdr[0])
		}
		if err := a.copyFrom(br, size); err != nil {
			return err
		}
	}
}

// assembler turns a byte stream into lines. It keeps at most MaxLineBytes of a line and
// discards the rest, so an endless line cannot exhaust memory.
type assembler struct {
	s       *sink
	source  agentv1.LogLine_Source
	buf     []byte
	dropped bool
}

func newAssembler(s *sink, source agentv1.LogLine_Source) *assembler {
	return &assembler{s: s, source: source}
}

// copyFrom feeds n bytes (all until EOF when n < 0) through the assembler.
func (a *assembler) copyFrom(r io.Reader, n int64) error {
	chunk := make([]byte, 32<<10)
	for n != 0 {
		want := int64(len(chunk))
		if n > 0 && n < want {
			want = n
		}
		got, err := r.Read(chunk[:want])
		if got > 0 {
			if werr := a.write(chunk[:got]); werr != nil {
				return werr
			}
			if n > 0 {
				n -= int64(got)
			}
		}
		if err != nil {
			if n > 0 && errors.Is(err, io.EOF) {
				return io.ErrUnexpectedEOF
			}
			return err
		}
	}
	return nil
}

func (a *assembler) write(p []byte) error {
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			a.keep(p)
			return nil
		}
		a.keep(p[:i])
		if err := a.emit(); err != nil {
			return err
		}
		p = p[i+1:]
	}
	return nil
}

func (a *assembler) keep(p []byte) {
	room := MaxLineBytes + 64 - len(a.buf) // 64 bytes of slack for the timestamp prefix
	if room <= 0 {
		a.dropped = true
		return
	}
	if len(p) > room {
		p, a.dropped = p[:room], true
	}
	a.buf = append(a.buf, p...)
}

func (a *assembler) emit() error {
	line := bytes.TrimSuffix(a.buf, []byte{'\r'})
	ts, text := splitTimestamp(line)
	a.buf, a.dropped = a.buf[:0], false
	return a.s.add(ts, a.source, text)
}

// splitTimestamp separates the RFC 3339 prefix that timestamps=1 adds. A line without one
// (a runtime that ignores the flag) keeps its text and gets the current time.
func splitTimestamp(line []byte) (time.Time, []byte) {
	if i := bytes.IndexByte(line, ' '); i > 19 && i <= 40 {
		if t, err := time.Parse(time.RFC3339Nano, string(line[:i])); err == nil {
			return t, line[i+1:]
		}
	}
	return time.Now(), line
}
