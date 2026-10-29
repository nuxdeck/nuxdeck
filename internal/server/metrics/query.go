// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"slices"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/tsdb"
	"github.com/prometheus/prometheus/tsdb/chunkenc"
)

// Query limits protect server memory.
const (
	MaxPointsPerSeries = 11000
	MaxRange           = 120 * 24 * time.Hour
	MaxSeries          = 200
	autoPoints         = 1000
	downStep           = 5 * time.Minute
	// fullResMaxRange is the longest range served from full-resolution data; 7 days
	// (MET-6) comes from the 5-minute averages.
	fullResMaxRange = 48 * time.Hour
	minStep         = time.Second
)

// Resolutions reported in results.
const (
	ResolutionFull = "full"
	Resolution5m   = "5m"
)

// ErrInvalidQuery wraps every validation failure; Field names the offending parameter.
type ErrInvalidQuery struct {
	Field string
	Hint  string
}

func (e *ErrInvalidQuery) Error() string { return "invalid " + e.Field + ": " + e.Hint }

// Query selects one metric of one target over a range.
type Query struct {
	TargetType string // TargetHost or TargetContainer
	Target     string // inventory ID
	Metric     string
	// Labels restricts the result to series whose labels equal these (names from allowedLabels).
	Labels   map[string]string
	From, To time.Time
	// Step is the bucket width; zero picks one for about 1000 points. It is raised to
	// the resolution's floor and so that a series has at most MaxPointsPerSeries points.
	Step time.Duration
}

// Point is one sample, encoded as [unix_ms, value].
type Point struct {
	TS    int64
	Value float64
}

// MarshalJSON renders [ts, value].
func (p Point) MarshalJSON() ([]byte, error) { return json.Marshal([2]float64{float64(p.TS), p.Value}) }

// Series is one result series.
type Series struct {
	Metric string            `json:"metric"`
	Labels map[string]string `json:"labels"`
	Points []Point           `json:"points"`
}

// Result is the answer to a Query.
type Result struct {
	Resolution string `json:"resolution"`
	// Kind is "gauge" or "rate": a counter metric is returned as its per-second rate.
	Kind        string   `json:"kind"`
	Unit        string   `json:"unit"`
	StepSeconds int64    `json:"step_seconds"`
	From        int64    `json:"from"`
	To          int64    `json:"to"`
	Series      []Series `json:"series"`
}

// plan validates q and decides resolution and step.
func (s *Service) plan(q Query) (res string, step time.Duration, err error) {
	def, ok := Lookup(q.Metric)
	if !ok {
		return "", 0, &ErrInvalidQuery{"metric", "Use a metric from the catalogue."}
	}
	if !def.appliesTo(q.TargetType) {
		return "", 0, &ErrInvalidQuery{"metric", "This metric is not reported for that kind of target."}
	}
	for k, v := range q.Labels {
		if !allowedLabels[k] || len(v) > maxLabelValueSize {
			return "", 0, &ErrInvalidQuery{"label", "Use name:value with a label name such as mode, cpu, mount or interface."}
		}
	}
	if !q.To.After(q.From) {
		return "", 0, &ErrInvalidQuery{"to", "Use a time after from."}
	}
	rng := q.To.Sub(q.From)
	if rng > MaxRange {
		return "", 0, &ErrInvalidQuery{"from", fmt.Sprintf("Query at most %d days at a time.", int(MaxRange.Hours()/24))}
	}
	if q.Step < 0 {
		return "", 0, &ErrInvalidQuery{"step", "Use a positive number of seconds."}
	}

	res, floor := ResolutionFull, minStep
	if q.From.Before(s.now().Add(-s.opts.FullRetention)) || rng > fullResMaxRange {
		res, floor = Resolution5m, downStep
	}
	step = q.Step
	if step == 0 {
		step = rng / autoPoints
	}
	step = max(step, floor, (rng/MaxPointsPerSeries/time.Second+1)*time.Second)
	return res, step.Truncate(time.Second), nil
}

// Query returns the series of q at the best resolution for its range.
func (s *Service) Query(ctx context.Context, q Query) (Result, error) {
	res, step, err := s.plan(q)
	if err != nil {
		return Result{}, err
	}
	def, _ := Lookup(q.Metric)
	fromMS, toMS, stepMS := q.From.UnixMilli(), q.To.UnixMilli(), step.Milliseconds()
	readFrom := fromMS
	if def.Kind == KindCounter {
		readFrom -= stepMS // one extra bucket so the first rate has a predecessor
	}
	matchers := []*labels.Matcher{
		labels.MustNewMatcher(labels.MatchEqual, nameLabel, q.Metric),
		labels.MustNewMatcher(labels.MatchEqual, "target_type", q.TargetType),
		labels.MustNewMatcher(labels.MatchEqual, "target", q.Target),
	}
	for k, v := range q.Labels {
		matchers = append(matchers, labels.MustNewMatcher(labels.MatchEqual, k, v))
	}

	lbls := map[string]labels.Labels{}
	read := func(db *tsdb.DB, from, to int64) (map[string][]Point, error) {
		pts, l, err := readSeries(ctx, db, from, to, matchers)
		maps.Copy(lbls, l)
		return pts, err
	}

	var raw map[string][]Point
	switch res {
	case ResolutionFull:
		if raw, err = read(s.store.full, readFrom, toMS); err != nil {
			return Result{}, err
		}
	default:
		// 5m averages up to the downsampling watermark, full-resolution data averaged into
		// 5m buckets after it, so the newest hour is not missing between job runs.
		wm := s.watermark()
		if raw, err = read(s.store.down, readFrom, min(toMS, wm)); err != nil {
			return Result{}, err
		}
		if toMS > wm {
			tail, err := read(s.store.full, max(readFrom, wm), toMS)
			if err != nil {
				return Result{}, err
			}
			for k, pts := range tail {
				raw[k] = append(raw[k], bucketAvg(pts, downStep.Milliseconds())...)
			}
		}
	}

	kind := KindGauge
	if def.Kind == KindCounter {
		kind = "rate"
	}
	out := Result{Resolution: res, Kind: kind, Unit: def.Unit, StepSeconds: int64(step / time.Second), From: fromMS, To: toMS, Series: []Series{}}
	keys := slices.Sorted(maps.Keys(raw))
	if len(keys) > MaxSeries {
		keys = keys[:MaxSeries]
	}
	for _, k := range keys {
		pts := raw[k]
		pts = bucketAvg(pts, stepMS)
		if def.Kind == KindCounter {
			pts = rate(pts, fromMS-fromMS%stepMS)
		}
		if len(pts) == 0 {
			continue
		}
		l := lbls[k].Map()
		delete(l, nameLabel)
		out.Series = append(out.Series, Series{Metric: q.Metric, Labels: l, Points: pts})
	}
	return out, nil
}

// readSeries loads every sample of the series matching ms in [from, to], keyed by label string.
func readSeries(ctx context.Context, db *tsdb.DB, from, to int64, ms []*labels.Matcher) (map[string][]Point, map[string]labels.Labels, error) {
	pts, lbls := map[string][]Point{}, map[string]labels.Labels{}
	if to < from {
		return pts, lbls, nil
	}
	q, err := db.Querier(from, to)
	if err != nil {
		return nil, nil, fmt.Errorf("open querier: %w", err)
	}
	defer func() { _ = q.Close() }()
	set := q.Select(ctx, false, nil, ms...)
	for set.Next() {
		s := set.At()
		key := s.Labels().String()
		lbls[key] = s.Labels()
		it := s.Iterator(nil)
		for it.Next() == chunkenc.ValFloat {
			t, v := it.At()
			if t >= from && t <= to {
				pts[key] = append(pts[key], Point{TS: t, Value: v})
			}
		}
		if err := it.Err(); err != nil {
			return nil, nil, fmt.Errorf("read series: %w", err)
		}
	}
	if err := set.Err(); err != nil {
		return nil, nil, fmt.Errorf("select series: %w", err)
	}
	return pts, lbls, nil
}

// bucketAvg averages points into buckets aligned to multiples of stepMS, stamped at the
// bucket start. Input must be time-ordered.
func bucketAvg(in []Point, stepMS int64) []Point {
	if len(in) == 0 {
		return nil
	}
	out := make([]Point, 0, min(len(in), 1024))
	var sum float64
	var n int
	cur := in[0].TS - in[0].TS%stepMS
	flush := func() {
		if n > 0 {
			out = append(out, Point{TS: cur, Value: sum / float64(n)})
		}
	}
	for _, p := range in {
		if math.IsNaN(p.Value) {
			continue
		}
		b := p.TS - p.TS%stepMS
		if b != cur {
			flush()
			cur, sum, n = b, 0, 0
		}
		sum += p.Value
		n++
	}
	flush()
	return out
}

// rate turns cumulative counter points into per-second rates, keeping points at or after
// notBefore. A decrease (counter reset) yields no point for that interval.
func rate(in []Point, notBefore int64) []Point {
	out := make([]Point, 0, len(in))
	for i := 1; i < len(in); i++ {
		dt := in[i].TS - in[i-1].TS
		dv := in[i].Value - in[i-1].Value
		if dt <= 0 || dv < 0 || in[i].TS < notBefore {
			continue
		}
		out = append(out, Point{TS: in[i].TS, Value: dv / float64(dt) * 1000})
	}
	return out
}
