// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/pkg/client"
)

const requestTimeout = 30 * time.Second

// APIError is a non-2xx answer from nuxd in the shared error shape. Code and Hint come from the server.
type APIError struct {
	Status  int
	Code    string
	Message string
	Hint    string
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("nuxd answered HTTP %d", e.Status)
	}
	return e.Code + ": " + e.Message
}

// conn is an authenticated connection to one nuxd. The token is sent as a Bearer header on
// every request, which token auth exempts from the CSRF check.
type conn struct {
	server string
	token  string
	http   *http.Client // REST calls, bounded by requestTimeout
	stream *http.Client // WebSocket, no overall timeout so logs can stay open
	api    *client.ClientWithResponses
}

func dial(server, token string, t trust) (*conn, error) {
	tr, err := t.transport()
	if err != nil {
		return nil, err
	}
	c := &conn{
		server: server,
		token:  token,
		http:   &http.Client{Transport: tr, Timeout: requestTimeout},
		stream: &http.Client{Transport: tr},
	}
	bearer := func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+token)
		return nil
	}
	api, err := client.NewClientWithResponses(server, client.WithHTTPClient(c.http), client.WithRequestEditorFn(bearer))
	if err != nil {
		return nil, errcode.Wrap(errcode.CLIArg002, "server URL", err)
	}
	c.api = api
	return c, nil
}

// transportError marks a request that never got an answer.
func transportError(err error) error {
	return errcode.Wrap(errcode.CLINet001, "request to nuxd failed", err)
}

// responseError turns a non-2xx status into an APIError and returns nil for 2xx.
func responseError(status int, body []byte) error {
	if status >= 200 && status < 300 {
		return nil
	}
	e := &APIError{Status: status}
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Hint    string `json:"hint"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &env) == nil {
		e.Code, e.Message, e.Hint = env.Error.Code, env.Error.Message, env.Error.Hint
	}
	return e
}
