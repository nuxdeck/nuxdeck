// SPDX-License-Identifier: Apache-2.0

//go:build race

package metrics

// raceEnabled is true under the race detector, whose overhead invalidates CPU and allocation budgets.
const raceEnabled = true
