// SPDX-License-Identifier: Apache-2.0

// Package openapi embeds the Nux Deck REST API description, api/openapi.yaml. The server serves it
// and the generated clients are built from it (make api).
package openapi

import _ "embed"

// Document is the OpenAPI 3.1 description of every /api/v1 route.
//
//go:embed openapi.yaml
var Document []byte
