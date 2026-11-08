// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/pkg/client"
)

const pageSize = 50

// pager holds the paging flags of list commands.
type pager struct {
	Limit  int
	Cursor string
}

func (p *pager) register(fs *flag.FlagSet) {
	fs.IntVar(&p.Limit, "limit", pageSize, "page size, 1 to 500")
	fs.StringVar(&p.Cursor, "cursor", "", "continue from the cursor printed by the previous page")
}

func (p pager) apply(limit **client.Limit, cursor **client.Cursor) {
	if p.Limit != pageSize {
		l := p.Limit
		*limit = &l
	}
	if p.Cursor != "" {
		c := p.Cursor
		*cursor = &c
	}
}

func (a *app) login(ctx context.Context, args []string) error {
	var s shared
	var tokenFile string
	var tokenStdin bool
	fs := a.newFlagSet("login", "login [--server URL] (--token-file FILE | --token-stdin)",
		"Signs in to nuxd with a personal API token. The token is checked with GET /api/v1/me and then\n"+
			"stored in the nux config file (mode 0600). Create the token in the web UI under your account.")
	s.register(fs, false)
	fs.StringVar(&tokenFile, "token-file", "", "read the token from this file")
	fs.BoolVar(&tokenStdin, "token-stdin", false, "read the token from standard input")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if err := exactArgs(fs, pos, 0); err != nil {
		return err
	}

	token, err := a.loginToken(s, tokenFile, tokenStdin)
	if err != nil {
		return err
	}
	st, err := a.resolve(s)
	if err != nil {
		return err
	}

	me, err := a.verifyToken(ctx, st.server, token, &st.trust)
	if err != nil {
		return err
	}

	path, err := a.configPath()
	if err != nil {
		return err
	}
	cfg := Config{Server: st.server, Token: token, CAFile: st.trust.CAFile, Pin: st.trust.Pin}
	if err := SaveConfig(path, cfg); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(a.env.Stdout, "Signed in to %s as %s.\n", st.server, me.User.Email)
	_, _ = fmt.Fprintf(a.env.Stderr, "warning: the API token is stored in clear text in %s. Prefer NUX_TOKEN in CI.\n", path)
	return nil
}

// loginToken takes the token from exactly one source, so a mistake never silently picks the wrong one.
func (a *app) loginToken(s shared, tokenFile string, tokenStdin bool) (string, error) {
	sources := 0
	for _, set := range []bool{tokenFile != "", tokenStdin, s.Token != ""} {
		if set {
			sources++
		}
	}
	if sources > 1 {
		return "", errcode.New(errcode.CLIArg002, "give the token by one of --token-file, --token-stdin or --token")
	}
	switch {
	case tokenFile != "":
		return requireToken(readFile(tokenFile))
	case tokenStdin:
		data, err := io.ReadAll(a.env.Stdin)
		if err != nil {
			return "", errcode.Wrap(errcode.CLIArg002, "read token from stdin", err)
		}
		return requireToken(strings.TrimSpace(string(data)), nil)
	case s.Token != "":
		return s.Token, nil
	case a.env.Getenv("NUX_TOKEN") != "":
		return a.env.Getenv("NUX_TOKEN"), nil
	}
	return "", errcode.New(errcode.CLIArg002, "no token given; use --token-file FILE, --token-stdin or NUX_TOKEN")
}

func requireToken(token string, err error) (string, error) {
	if err != nil {
		return "", err
	}
	if token == "" {
		return "", errcode.New(errcode.CLIArg002, "the token is empty")
	}
	return token, nil
}

// verifyToken calls GET /me. If the certificate chain is untrusted and no trust was configured,
// it shows the fingerprint and asks once before pinning it (trust on first use).
func (a *app) verifyToken(ctx context.Context, server, token string, t *trust) (*client.Session, error) {
	me, err := a.meWith(ctx, server, token, *t)
	if err == nil || !isUntrusted(err) || t.Pin != "" || t.CAFile != "" || t.Insecure {
		return me, err
	}
	u, perr := url.Parse(server)
	if perr != nil {
		return nil, perr
	}
	fp, perr := probeFingerprint(ctx, u)
	if perr != nil {
		return nil, perr
	}
	_, _ = fmt.Fprintf(a.env.Stderr, "%s presented a certificate the system does not trust.\nSHA-256 fingerprint: %s\n"+
		"Trust it only if you have checked this fingerprint on the server itself.\n", server, fp)
	if !a.confirm("Trust this certificate? [y/N] ") {
		return nil, errcode.Wrap(errcode.CLINet002, "certificate not trusted", err)
	}
	t.Pin = fp
	return a.meWith(ctx, server, token, *t)
}

func (a *app) meWith(ctx context.Context, server, token string, t trust) (*client.Session, error) {
	c, err := dial(server, token, t)
	if err != nil {
		return nil, err
	}
	rsp, err := c.api.GetMeWithResponse(ctx)
	if err != nil {
		return nil, transportError(err)
	}
	if err := responseError(rsp.StatusCode(), rsp.Body); err != nil {
		return nil, err
	}
	if rsp.JSON200 == nil {
		return nil, errcode.New(errcode.APIInt001, "nuxd sent an unexpected answer to GET /me")
	}
	return rsp.JSON200, nil
}

func (a *app) logout(args []string) error {
	fs := a.newFlagSet("logout", "logout", "Removes the stored sign-in from this machine. The API token itself stays valid;\n"+
		"revoke it in the web UI under your account if it is no longer needed.")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if err := exactArgs(fs, pos, 0); err != nil {
		return err
	}
	path, err := a.configPath()
	if err != nil {
		return err
	}
	removed, err := RemoveConfig(path)
	if err != nil {
		return err
	}
	if !removed {
		_, _ = fmt.Fprintln(a.env.Stdout, "Not signed in on this machine.")
		return nil
	}
	_, _ = fmt.Fprintf(a.env.Stdout, "Signed out; removed %s.\n", path)
	return nil
}

// ---- hosts ----

func (a *app) hosts(ctx context.Context, args []string) error {
	sub, rest := splitSub(args)
	switch sub {
	case "", "ls":
		return a.hostsLs(ctx, rest)
	case "get":
		return a.hostsGet(ctx, rest)
	}
	return unknownSub("hosts", sub)
}

func (a *app) hostsLs(ctx context.Context, args []string) error {
	var s shared
	var p pager
	var status string
	var includeGone bool
	var tags stringList
	fs := a.newFlagSet("hosts ls", "hosts ls [flags]", "Lists hosts known to nuxd, with their status and last report.")
	s.register(fs, true)
	p.register(fs)
	fs.StringVar(&status, "status", "", "only hosts with this status: online or offline")
	fs.BoolVar(&includeGone, "include-gone", false, "include hosts that have gone")
	fs.Var(&tags, "tag", "tag selector key or key:value; repeatable")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if err := exactArgs(fs, pos, 0); err != nil {
		return err
	}
	if err := s.validateOutput(); err != nil {
		return err
	}
	params := &client.ListHostsParams{}
	p.apply(&params.Limit, &params.Cursor)
	switch status {
	case "":
	case "online", "offline":
		st := client.ListHostsParamsStatus(status)
		params.Status = &st
	default:
		return errcode.New(errcode.CLIArg002, "--status must be online or offline, got %q", status)
	}
	if includeGone {
		v := client.ListHostsParamsIncludeGoneTrue
		params.IncludeGone = &v
	}
	if len(tags) > 0 {
		t := client.Tag(tags)
		params.Tag = &t
	}
	c, err := a.connect(s)
	if err != nil {
		return err
	}
	rsp, err := c.api.ListHostsWithResponse(ctx, params)
	if err != nil {
		return transportError(err)
	}
	if err := responseError(rsp.StatusCode(), rsp.Body); err != nil {
		return err
	}
	if rsp.JSON200 == nil {
		return errcode.New(errcode.APIInt001, "nuxd sent an unexpected answer to hosts")
	}
	page := rsp.JSON200
	if s.Output == "json" {
		return a.emitJSON(page)
	}
	rows := make([][]string, 0, len(page.Items))
	for _, h := range page.Items {
		rows = append(rows, []string{h.Id, h.Hostname, string(h.Status), h.Os, h.Arch, strconv.Itoa(h.CpuCount), fmtTime(h.LastSeenAt)})
	}
	if err := a.table([]string{"ID", "HOSTNAME", "STATUS", "OS", "ARCH", "CPUS", "LAST SEEN"}, rows); err != nil {
		return err
	}
	a.hintMore(page.NextCursor, "hosts ls")
	return nil
}

func (a *app) hostsGet(ctx context.Context, args []string) error {
	var s shared
	fs := a.newFlagSet("hosts get", "hosts get ID [flags]", "Shows one host by ID.")
	s.register(fs, true)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if err := exactArgs(fs, pos, 1); err != nil {
		return err
	}
	if err := s.validateOutput(); err != nil {
		return err
	}
	c, err := a.connect(s)
	if err != nil {
		return err
	}
	rsp, err := c.api.GetHostWithResponse(ctx, pos[0])
	if err != nil {
		return transportError(err)
	}
	if err := responseError(rsp.StatusCode(), rsp.Body); err != nil {
		return err
	}
	h := rsp.JSON200
	if h == nil {
		return errcode.New(errcode.APIInt001, "nuxd sent an unexpected answer to hosts get")
	}
	if s.Output == "json" {
		return a.emitJSON(h)
	}
	return a.fields([][2]string{
		{"ID", h.Id},
		{"Hostname", h.Hostname},
		{"Status", string(h.Status)},
		{"Agent", h.AgentId},
		{"OS", h.Os},
		{"Distro", h.Distro},
		{"Kernel", h.Kernel},
		{"Arch", h.Arch},
		{"CPUs", strconv.Itoa(h.CpuCount)},
		{"Memory bytes", strconv.FormatInt(h.MemoryBytes, 10)},
		{"First seen", fmtTime(h.FirstSeenAt)},
		{"Last seen", fmtTime(h.LastSeenAt)},
		{"Owner", h.Owner},
	})
}

// ---- containers ----

func (a *app) containers(ctx context.Context, args []string) error {
	sub, rest := splitSub(args)
	switch sub {
	case "", "ls":
		return a.containersLs(ctx, rest)
	case "get":
		return a.containersGet(ctx, rest)
	}
	return unknownSub("containers", sub)
}

func (a *app) containersLs(ctx context.Context, args []string) error {
	var s shared
	var p pager
	var host, state string
	var includeGone bool
	fs := a.newFlagSet("containers ls", "containers ls [flags]", "Lists containers across hosts.")
	s.register(fs, true)
	p.register(fs)
	fs.StringVar(&host, "host", "", "only containers on this host ID")
	fs.StringVar(&state, "state", "", "only containers in this state, for example running")
	fs.BoolVar(&includeGone, "include-gone", false, "include containers that have gone")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if err := exactArgs(fs, pos, 0); err != nil {
		return err
	}
	if err := s.validateOutput(); err != nil {
		return err
	}
	params := &client.ListContainersParams{}
	p.apply(&params.Limit, &params.Cursor)
	if host != "" {
		params.HostId = &host
	}
	if state != "" {
		params.State = &state
	}
	if includeGone {
		v := client.ListContainersParamsIncludeGoneTrue
		params.IncludeGone = &v
	}
	c, err := a.connect(s)
	if err != nil {
		return err
	}
	rsp, err := c.api.ListContainersWithResponse(ctx, params)
	if err != nil {
		return transportError(err)
	}
	if err := responseError(rsp.StatusCode(), rsp.Body); err != nil {
		return err
	}
	if rsp.JSON200 == nil {
		return errcode.New(errcode.APIInt001, "nuxd sent an unexpected answer to containers")
	}
	page := rsp.JSON200
	if s.Output == "json" {
		return a.emitJSON(page)
	}
	rows := make([][]string, 0, len(page.Items))
	for _, ct := range page.Items {
		rows = append(rows, []string{ct.Id, ct.Name, ct.Image, ct.State, ct.HostId, ct.Runtime})
	}
	if err := a.table([]string{"ID", "NAME", "IMAGE", "STATE", "HOST", "RUNTIME"}, rows); err != nil {
		return err
	}
	a.hintMore(page.NextCursor, "containers ls")
	return nil
}

func (a *app) containersGet(ctx context.Context, args []string) error {
	var s shared
	fs := a.newFlagSet("containers get", "containers get ID [flags]", "Shows one container by ID.")
	s.register(fs, true)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if err := exactArgs(fs, pos, 1); err != nil {
		return err
	}
	if err := s.validateOutput(); err != nil {
		return err
	}
	c, err := a.connect(s)
	if err != nil {
		return err
	}
	ct, err := getContainer(ctx, c, pos[0])
	if err != nil {
		return err
	}
	if s.Output == "json" {
		return a.emitJSON(ct)
	}
	return a.fields([][2]string{
		{"ID", ct.Id},
		{"Name", ct.Name},
		{"Image", ct.Image},
		{"State", ct.State},
		{"Host", ct.HostId},
		{"Runtime", ct.Runtime},
		{"Restarts", strconv.Itoa(ct.RestartCount)},
		{"Owner", ct.Owner},
	})
}

func getContainer(ctx context.Context, c *conn, id string) (*client.Container, error) {
	rsp, err := c.api.GetContainerWithResponse(ctx, id)
	if err != nil {
		return nil, transportError(err)
	}
	if err := responseError(rsp.StatusCode(), rsp.Body); err != nil {
		return nil, err
	}
	if rsp.JSON200 == nil {
		return nil, errcode.New(errcode.APIInt001, "nuxd sent an unexpected answer to containers get")
	}
	return rsp.JSON200, nil
}

// ---- checks ----

func (a *app) checks(ctx context.Context, args []string) error {
	sub, rest := splitSub(args)
	switch sub {
	case "", "ls":
		return a.checksLs(ctx, rest)
	case "get":
		return a.checksGet(ctx, rest)
	case "run":
		return a.checksRun(ctx, rest)
	}
	return unknownSub("checks", sub)
}

func (a *app) checksLs(ctx context.Context, args []string) error {
	var s shared
	var p pager
	fs := a.newFlagSet("checks ls", "checks ls [flags]", "Lists uptime checks with their current state.")
	s.register(fs, true)
	p.register(fs)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if err := exactArgs(fs, pos, 0); err != nil {
		return err
	}
	if err := s.validateOutput(); err != nil {
		return err
	}
	params := &client.ListChecksParams{}
	p.apply(&params.Limit, &params.Cursor)
	c, err := a.connect(s)
	if err != nil {
		return err
	}
	rsp, err := c.api.ListChecksWithResponse(ctx, params)
	if err != nil {
		return transportError(err)
	}
	if err := responseError(rsp.StatusCode(), rsp.Body); err != nil {
		return err
	}
	if rsp.JSON200 == nil {
		return errcode.New(errcode.APIInt001, "nuxd sent an unexpected answer to checks")
	}
	page := rsp.JSON200
	if s.Output == "json" {
		return a.emitJSON(page)
	}
	rows := make([][]string, 0, len(page.Items))
	for _, ck := range page.Items {
		rows = append(rows, []string{ck.Id, ck.Name, string(ck.Type), string(ck.Status.State), strconv.Itoa(ck.IntervalS), fmtTimePtr(ck.Status.LastChecked)})
	}
	if err := a.table([]string{"ID", "NAME", "TYPE", "STATE", "INTERVAL S", "LAST CHECKED"}, rows); err != nil {
		return err
	}
	a.hintMore(page.NextCursor, "checks ls")
	return nil
}

func (a *app) checksGet(ctx context.Context, args []string) error {
	var s shared
	fs := a.newFlagSet("checks get", "checks get ID [flags]", "Shows one check and its current status.")
	s.register(fs, true)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if err := exactArgs(fs, pos, 1); err != nil {
		return err
	}
	if err := s.validateOutput(); err != nil {
		return err
	}
	c, err := a.connect(s)
	if err != nil {
		return err
	}
	rsp, err := c.api.GetCheckWithResponse(ctx, pos[0])
	if err != nil {
		return transportError(err)
	}
	if err := responseError(rsp.StatusCode(), rsp.Body); err != nil {
		return err
	}
	ck := rsp.JSON200
	if ck == nil {
		return errcode.New(errcode.APIInt001, "nuxd sent an unexpected answer to checks get")
	}
	if s.Output == "json" {
		return a.emitJSON(ck)
	}
	return a.fields([][2]string{
		{"ID", ck.Id},
		{"Name", ck.Name},
		{"Type", string(ck.Type)},
		{"Runner", ck.Runner},
		{"Enabled", strconv.FormatBool(ck.Enabled)},
		{"Interval s", strconv.Itoa(ck.IntervalS)},
		{"State", string(ck.Status.State)},
		{"Since", fmtTimePtr(ck.Status.Since)},
		{"Last checked", fmtTimePtr(ck.Status.LastChecked)},
		{"Last detail", ck.Status.LastDetail},
	})
}

func (a *app) checksRun(ctx context.Context, args []string) error {
	var s shared
	fs := a.newFlagSet("checks run", "checks run ID [flags]", "Runs one check now and prints the result. Rate limited by the server.")
	s.register(fs, true)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if err := exactArgs(fs, pos, 1); err != nil {
		return err
	}
	if err := s.validateOutput(); err != nil {
		return err
	}
	c, err := a.connect(s)
	if err != nil {
		return err
	}
	rsp, err := c.api.RunCheckWithResponse(ctx, pos[0], &client.RunCheckParams{})
	if err != nil {
		return transportError(err)
	}
	if err := responseError(rsp.StatusCode(), rsp.Body); err != nil {
		return err
	}
	res := rsp.JSON200
	if res == nil {
		return errcode.New(errcode.APIInt001, "nuxd sent an unexpected answer to checks run")
	}
	if s.Output == "json" {
		return a.emitJSON(res)
	}
	return a.fields([][2]string{
		{"Status", res.Status},
		{"Latency ms", strconv.FormatInt(res.LatencyMs, 10)},
		{"Error code", res.ErrorCode},
		{"Detail", res.Detail},
		{"Time", fmtTime(res.Ts)},
	})
}

// ---- alerts ----

func (a *app) alerts(ctx context.Context, args []string) error {
	sub, rest := splitSub(args)
	switch sub {
	case "", "ls":
		return a.alertsLs(ctx, rest)
	case "get":
		return a.alertsGet(ctx, rest)
	case "ack":
		return a.alertsAck(ctx, rest)
	}
	return unknownSub("alerts", sub)
}

func (a *app) alertsLs(ctx context.Context, args []string) error {
	var s shared
	var p pager
	var state, severity, itemID, ruleID string
	fs := a.newFlagSet("alerts ls", "alerts ls [flags]", "Lists alerts, newest first.")
	s.register(fs, true)
	p.register(fs)
	fs.StringVar(&state, "state", "", "only alerts in this state: open, acked or resolved")
	fs.StringVar(&severity, "severity", "", "only alerts with this severity: info, warning or critical")
	fs.StringVar(&itemID, "item-id", "", "only alerts about this host, container or check ID")
	fs.StringVar(&ruleID, "rule-id", "", "only alerts from this rule ID")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if err := exactArgs(fs, pos, 0); err != nil {
		return err
	}
	if err := s.validateOutput(); err != nil {
		return err
	}
	params := &client.ListAlertsParams{}
	p.apply(&params.Limit, &params.Cursor)
	if state != "" {
		v := client.ListAlertsParamsState(state)
		params.State = &v
	}
	if severity != "" {
		v := client.ListAlertsParamsSeverity(severity)
		params.Severity = &v
	}
	if itemID != "" {
		params.ItemId = &itemID
	}
	if ruleID != "" {
		params.RuleId = &ruleID
	}
	c, err := a.connect(s)
	if err != nil {
		return err
	}
	rsp, err := c.api.ListAlertsWithResponse(ctx, params)
	if err != nil {
		return transportError(err)
	}
	if err := responseError(rsp.StatusCode(), rsp.Body); err != nil {
		return err
	}
	if rsp.JSON200 == nil {
		return errcode.New(errcode.APIInt001, "nuxd sent an unexpected answer to alerts")
	}
	page := rsp.JSON200
	if s.Output == "json" {
		return a.emitJSON(page)
	}
	rows := make([][]string, 0, len(page.Items))
	for _, al := range page.Items {
		rows = append(rows, []string{al.Id, string(al.Severity), string(al.State), al.RuleName, al.ItemName, al.Summary, fmtTime(al.OpenedAt)})
	}
	if err := a.table([]string{"ID", "SEVERITY", "STATE", "RULE", "ITEM", "SUMMARY", "OPENED"}, rows); err != nil {
		return err
	}
	a.hintMore(page.NextCursor, "alerts ls")
	return nil
}

func (a *app) alertsGet(ctx context.Context, args []string) error {
	var s shared
	fs := a.newFlagSet("alerts get", "alerts get ID [flags]", "Shows one alert.")
	s.register(fs, true)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if err := exactArgs(fs, pos, 1); err != nil {
		return err
	}
	if err := s.validateOutput(); err != nil {
		return err
	}
	c, err := a.connect(s)
	if err != nil {
		return err
	}
	rsp, err := c.api.GetAlertWithResponse(ctx, pos[0])
	if err != nil {
		return transportError(err)
	}
	if err := responseError(rsp.StatusCode(), rsp.Body); err != nil {
		return err
	}
	al := rsp.JSON200
	if al == nil {
		return errcode.New(errcode.APIInt001, "nuxd sent an unexpected answer to alerts get")
	}
	if s.Output == "json" {
		return a.emitJSON(al)
	}
	return a.fields([][2]string{
		{"ID", al.Id},
		{"State", string(al.State)},
		{"Severity", string(al.Severity)},
		{"Rule", al.RuleName},
		{"Item", al.ItemName + " (" + al.ItemType + ")"},
		{"Summary", al.Summary},
		{"Opened", fmtTime(al.OpenedAt)},
		{"Acked by", derefString(al.AckedBy)},
		{"Resolved", fmtTimePtr(al.ResolvedAt)},
		{"Link", al.Link},
	})
}

func (a *app) alertsAck(ctx context.Context, args []string) error {
	var s shared
	fs := a.newFlagSet("alerts ack", "alerts ack ID [flags]", "Acknowledges an open alert so that it stops paging. Resolved alerts cannot be acknowledged.")
	s.register(fs, true)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if err := exactArgs(fs, pos, 1); err != nil {
		return err
	}
	if err := s.validateOutput(); err != nil {
		return err
	}
	c, err := a.connect(s)
	if err != nil {
		return err
	}
	rsp, err := c.api.AckAlertWithResponse(ctx, pos[0], &client.AckAlertParams{})
	if err != nil {
		return transportError(err)
	}
	if err := responseError(rsp.StatusCode(), rsp.Body); err != nil {
		return err
	}
	if s.Output == "json" && rsp.JSON200 != nil {
		return a.emitJSON(rsp.JSON200)
	}
	_, err = fmt.Fprintf(a.env.Stdout, "Acknowledged alert %s.\n", pos[0])
	return err
}

// ---- silences ----

func (a *app) silences(ctx context.Context, args []string) error {
	sub, rest := splitSub(args)
	switch sub {
	case "", "ls":
		return a.silencesLs(ctx, rest)
	case "create":
		return a.silencesCreate(ctx, rest)
	case "rm":
		return a.silencesRm(ctx, rest)
	}
	return unknownSub("silences", sub)
}

func (a *app) silencesLs(ctx context.Context, args []string) error {
	var s shared
	var p pager
	var active bool
	fs := a.newFlagSet("silences ls", "silences ls [flags]", "Lists silences and maintenance windows.")
	s.register(fs, true)
	p.register(fs)
	fs.BoolVar(&active, "active", false, "only silences in force now")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if err := exactArgs(fs, pos, 0); err != nil {
		return err
	}
	if err := s.validateOutput(); err != nil {
		return err
	}
	params := &client.ListSilencesParams{}
	p.apply(&params.Limit, &params.Cursor)
	if active {
		v := client.ListSilencesParamsActiveTrue
		params.Active = &v
	}
	c, err := a.connect(s)
	if err != nil {
		return err
	}
	rsp, err := c.api.ListSilencesWithResponse(ctx, params)
	if err != nil {
		return transportError(err)
	}
	if err := responseError(rsp.StatusCode(), rsp.Body); err != nil {
		return err
	}
	if rsp.JSON200 == nil {
		return errcode.New(errcode.APIInt001, "nuxd sent an unexpected answer to silences")
	}
	page := rsp.JSON200
	if s.Output == "json" {
		return a.emitJSON(page)
	}
	rows := make([][]string, 0, len(page.Items))
	for _, sl := range page.Items {
		rows = append(rows, []string{sl.Id, string(sl.Kind), string(sl.State), fmtTime(sl.StartsAt), fmtTime(sl.EndsAt), sl.Reason})
	}
	if err := a.table([]string{"ID", "KIND", "STATE", "STARTS", "ENDS", "REASON"}, rows); err != nil {
		return err
	}
	a.hintMore(page.NextCursor, "silences ls")
	return nil
}

func (a *app) silencesCreate(ctx context.Context, args []string) error {
	var s shared
	var kind, reason, starts, ends string
	var duration time.Duration
	var ids, tags, severities stringList
	fs := a.newFlagSet("silences create", "silences create --reason TEXT (--duration D | --ends TIME) [flags]",
		"Creates a silence (mutes matching alerts) or a maintenance window. Each --id, --tag and --severity\n"+
			"narrows the selector; every non-empty field must match. TIME is RFC 3339, for example 2026-11-01T18:00:00Z.")
	s.register(fs, true)
	fs.StringVar(&kind, "kind", "silence", "silence or maintenance")
	fs.StringVar(&reason, "reason", "", "why the alerts are muted (required)")
	fs.StringVar(&starts, "starts", "", "start time, RFC 3339; default now")
	fs.StringVar(&ends, "ends", "", "end time, RFC 3339")
	fs.DurationVar(&duration, "duration", 0, "length from the start, for example 2h30m")
	fs.Var(&ids, "id", "item or rule ID to match; repeatable")
	fs.Var(&tags, "tag", "tag selector key or key:value; repeatable")
	fs.Var(&severities, "severity", "severity to match: info, warning or critical; repeatable")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if err := exactArgs(fs, pos, 0); err != nil {
		return err
	}
	if err := s.validateOutput(); err != nil {
		return err
	}
	body, err := silenceRequest(kind, reason, starts, ends, duration, ids, tags, severities, time.Now())
	if err != nil {
		return err
	}
	c, err := a.connect(s)
	if err != nil {
		return err
	}
	rsp, err := c.api.CreateSilenceWithResponse(ctx, &client.CreateSilenceParams{}, body)
	if err != nil {
		return transportError(err)
	}
	if err := responseError(rsp.StatusCode(), rsp.Body); err != nil {
		return err
	}
	sl := rsp.JSON201
	if sl == nil {
		return errcode.New(errcode.APIInt001, "nuxd sent an unexpected answer to silences create")
	}
	if s.Output == "json" {
		return a.emitJSON(sl)
	}
	_, err = fmt.Fprintf(a.env.Stdout, "Created %s %s, active until %s.\n", sl.Kind, sl.Id, fmtTime(sl.EndsAt))
	return err
}

// silenceRequest validates the flags before anything is sent, so a bad window never reaches the server.
func silenceRequest(kind, reason, starts, ends string, duration time.Duration, ids, tags, severities []string, now time.Time) (client.SilenceRequest, error) {
	var req client.SilenceRequest
	switch kind {
	case "silence":
		req.Kind = client.SilenceRequestKindSilence
	case "maintenance":
		req.Kind = client.SilenceRequestKindMaintenance
	default:
		return req, errcode.New(errcode.CLIArg002, "--kind must be silence or maintenance, got %q", kind)
	}
	if strings.TrimSpace(reason) == "" {
		return req, errcode.New(errcode.CLIArg002, "--reason is required")
	}
	req.Reason = reason
	req.StartsAt = now.UTC()
	if starts != "" {
		t, err := time.Parse(time.RFC3339, starts)
		if err != nil {
			return req, errcode.New(errcode.CLIArg002, "--starts must be RFC 3339, got %q", starts)
		}
		req.StartsAt = t.UTC()
	}
	switch {
	case ends != "" && duration > 0:
		return req, errcode.New(errcode.CLIArg002, "give --ends or --duration, not both")
	case ends != "":
		t, err := time.Parse(time.RFC3339, ends)
		if err != nil {
			return req, errcode.New(errcode.CLIArg002, "--ends must be RFC 3339, got %q", ends)
		}
		req.EndsAt = t.UTC()
	case duration > 0:
		req.EndsAt = req.StartsAt.Add(duration)
	default:
		return req, errcode.New(errcode.CLIArg002, "give --ends or --duration")
	}
	if !req.EndsAt.After(req.StartsAt) {
		return req, errcode.New(errcode.CLIArg002, "the silence must end after it starts")
	}
	var sel client.Selector
	if len(ids) > 0 {
		sel.Ids = &ids
	}
	if len(tags) > 0 {
		sel.Tags = &tags
	}
	if len(severities) > 0 {
		sevs := make([]client.SelectorSeverity, 0, len(severities))
		for _, v := range severities {
			sevs = append(sevs, client.SelectorSeverity(v))
		}
		sel.Severity = &sevs
	}
	req.Selector = sel
	return req, nil
}

func (a *app) silencesRm(ctx context.Context, args []string) error {
	var s shared
	fs := a.newFlagSet("silences rm", "silences rm ID [flags]", "Removes a silence so its alerts notify again.")
	s.register(fs, false)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if err := exactArgs(fs, pos, 1); err != nil {
		return err
	}
	c, err := a.connect(s)
	if err != nil {
		return err
	}
	rsp, err := c.api.DeleteSilenceWithResponse(ctx, pos[0], &client.DeleteSilenceParams{})
	if err != nil {
		return transportError(err)
	}
	if err := responseError(rsp.StatusCode(), rsp.Body); err != nil {
		return err
	}
	_, err = fmt.Fprintf(a.env.Stdout, "Removed silence %s.\n", pos[0])
	return err
}

// ---- agents ----

func (a *app) agents(ctx context.Context, args []string) error {
	sub, rest := splitSub(args)
	switch sub {
	case "", "ls":
		return a.agentsLs(ctx, rest)
	case "token":
		tsub, trest := splitSub(rest)
		if tsub != "create" {
			return unknownSub("agents token", tsub)
		}
		return a.agentsTokenCreate(ctx, trest)
	case "revoke":
		return a.agentsRevoke(ctx, rest)
	}
	return unknownSub("agents", sub)
}

// agentRow is one agent as seen through its host. The API has no agent list, so agents are
// derived from the host inventory, including hosts that have gone.
type agentRow struct {
	AgentID    string    `json:"agent_id"`
	Hostname   string    `json:"hostname"`
	Status     string    `json:"status"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

func (a *app) agentsLs(ctx context.Context, args []string) error {
	var s shared
	fs := a.newFlagSet("agents ls", "agents ls [flags]", "Lists enrolled agents, one per host that reported through them. Derived from the host\n"+
		"inventory because nuxd has no agent list endpoint yet.")
	s.register(fs, true)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if err := exactArgs(fs, pos, 0); err != nil {
		return err
	}
	if err := s.validateOutput(); err != nil {
		return err
	}
	c, err := a.connect(s)
	if err != nil {
		return err
	}
	hosts, err := allHosts(ctx, c)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	var out []agentRow
	for _, h := range hosts {
		if h.AgentId == "" || seen[h.AgentId] {
			continue
		}
		seen[h.AgentId] = true
		out = append(out, agentRow{AgentID: h.AgentId, Hostname: h.Hostname, Status: string(h.Status), LastSeenAt: h.LastSeenAt})
	}
	if s.Output == "json" {
		return a.emitJSON(out)
	}
	rows := make([][]string, 0, len(out))
	for _, r := range out {
		rows = append(rows, []string{r.AgentID, r.Hostname, r.Status, fmtTime(r.LastSeenAt)})
	}
	return a.table([]string{"AGENT ID", "HOSTNAME", "STATUS", "LAST SEEN"}, rows)
}

func (a *app) agentsTokenCreate(ctx context.Context, args []string) error {
	var s shared
	var ttl int
	fs := a.newFlagSet("agents token create", "agents token create [--ttl-seconds N] [flags]",
		"Creates a single-use enrolment token for `nux agent enroll`. The token is printed once; store it now.")
	s.register(fs, true)
	fs.IntVar(&ttl, "ttl-seconds", 0, "lifetime of the token in seconds; default is the server's (one hour)")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if err := exactArgs(fs, pos, 0); err != nil {
		return err
	}
	if err := s.validateOutput(); err != nil {
		return err
	}
	req := client.AgentTokenRequest{}
	if ttl > 0 {
		req.TtlSeconds = &ttl
	}
	c, err := a.connect(s)
	if err != nil {
		return err
	}
	rsp, err := c.api.CreateAgentTokenWithResponse(ctx, &client.CreateAgentTokenParams{}, req)
	if err != nil {
		return transportError(err)
	}
	if err := responseError(rsp.StatusCode(), rsp.Body); err != nil {
		return err
	}
	tok := rsp.JSON201
	if tok == nil {
		return errcode.New(errcode.APIInt001, "nuxd sent an unexpected answer to agents token create")
	}
	if s.Output == "json" {
		return a.emitJSON(tok)
	}
	_, _ = fmt.Fprintf(a.env.Stderr, "Enrolment token expires %s. It is shown once; store it now.\n", fmtTime(tok.ExpiresAt))
	_, err = fmt.Fprintln(a.env.Stdout, tok.Token)
	return err
}

func (a *app) agentsRevoke(ctx context.Context, args []string) error {
	var s shared
	fs := a.newFlagSet("agents revoke", "agents revoke ID [flags]", "Revokes an agent. Its host stops reporting until the agent is enrolled again.")
	s.register(fs, false)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if err := exactArgs(fs, pos, 1); err != nil {
		return err
	}
	c, err := a.connect(s)
	if err != nil {
		return err
	}
	rsp, err := c.api.RevokeAgentWithResponse(ctx, pos[0], &client.RevokeAgentParams{})
	if err != nil {
		return transportError(err)
	}
	if err := responseError(rsp.StatusCode(), rsp.Body); err != nil {
		return err
	}
	_, err = fmt.Fprintf(a.env.Stdout, "Revoked agent %s.\n", pos[0])
	return err
}

// ---- telemetry ----

func (a *app) telemetry(ctx context.Context, args []string) error {
	sub, rest := splitSub(args)
	if sub != "show" && sub != "" {
		return unknownSub("telemetry", sub)
	}
	var s shared
	fs := a.newFlagSet("telemetry show", "telemetry show [flags]", "Prints the exact telemetry payload nuxd would send today, so you can check what\n"+
		"leaves the install before you decide. Nothing is sent by this command.")
	s.register(fs, false)
	pos, err := parseArgs(fs, rest)
	if err != nil {
		return err
	}
	if err := exactArgs(fs, pos, 0); err != nil {
		return err
	}
	c, err := a.connect(s)
	if err != nil {
		return err
	}
	rsp, err := c.api.GetTelemetryPreviewWithResponse(ctx)
	if err != nil {
		return transportError(err)
	}
	if err := responseError(rsp.StatusCode(), rsp.Body); err != nil {
		return err
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, rsp.Body, "", "  "); err != nil {
		return errcode.Wrap(errcode.APIInt001, "nuxd sent malformed telemetry JSON", err)
	}
	_, err = fmt.Fprintln(a.env.Stdout, pretty.String())
	return err
}

// ---- shared helpers ----

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func fmtTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return fmtTime(*t)
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// allHosts pages through the host inventory, including hosts that have gone.
func allHosts(ctx context.Context, c *conn) ([]client.Host, error) {
	var all []client.Host
	var cursor *string
	for {
		params := &client.ListHostsParams{Cursor: cursor}
		v := client.ListHostsParamsIncludeGoneTrue
		params.IncludeGone = &v
		limit := 500
		params.Limit = &limit
		rsp, err := c.api.ListHostsWithResponse(ctx, params)
		if err != nil {
			return nil, transportError(err)
		}
		if err := responseError(rsp.StatusCode(), rsp.Body); err != nil {
			return nil, err
		}
		if rsp.JSON200 == nil {
			return nil, errcode.New(errcode.APIInt001, "nuxd sent an unexpected answer to hosts")
		}
		all = append(all, rsp.JSON200.Items...)
		next, more := nextPage(rsp.JSON200.NextCursor, cursor)
		if !more {
			return all, nil
		}
		cursor = next
	}
}

// nextPage returns the cursor for the following page. A server that repeats the cursor it was
// given would loop forever, so that stops the walk too.
func nextPage(next *string, current *string) (*string, bool) {
	if next == nil || *next == "" || (current != nil && *next == *current) {
		return nil, false
	}
	return next, true
}

// allContainers pages through the running container inventory.
func allContainers(ctx context.Context, c *conn) ([]client.Container, error) {
	var all []client.Container
	var cursor *string
	for {
		limit := 500
		rsp, err := c.api.ListContainersWithResponse(ctx, &client.ListContainersParams{Cursor: cursor, Limit: &limit})
		if err != nil {
			return nil, transportError(err)
		}
		if err := responseError(rsp.StatusCode(), rsp.Body); err != nil {
			return nil, err
		}
		if rsp.JSON200 == nil {
			return nil, errcode.New(errcode.APIInt001, "nuxd sent an unexpected answer to containers")
		}
		all = append(all, rsp.JSON200.Items...)
		next, more := nextPage(rsp.JSON200.NextCursor, cursor)
		if !more {
			return all, nil
		}
		cursor = next
	}
}
