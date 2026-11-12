// SPDX-License-Identifier: AGPL-3.0-only

//go:build race

package metrics_test

// raceEnabled is true under the race detector, which slows queries several times over.
const raceEnabled = true
