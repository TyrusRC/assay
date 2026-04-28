package matchers

import (
	"crypto/rand"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"strconv"
	"strings"
	"time"
)

// Random functions

const (
	alphaChars        = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	alphanumericChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	numericChars      = "0123456789"
	base36Chars       = "abcdefghijklmnopqrstuvwxyz0123456789"
)

// randString generates a random string of n characters from charset.
func randString(n int, charset string) string {
	if n <= 0 || len(charset) == 0 {
		return ""
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[mathrand.Intn(len(charset))]
	}
	return string(b)
}

// dslRandTextAlpha generates a random alpha string of length n.
func dslRandTextAlpha(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	n := int(toFloat64(args[0]))
	return randString(n, alphaChars)
}

// dslRandTextAlphanumeric generates a random alphanumeric string of length n.
func dslRandTextAlphanumeric(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	n := int(toFloat64(args[0]))
	return randString(n, alphanumericChars)
}

// dslRandTextNumeric generates a random numeric string of length n.
func dslRandTextNumeric(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	n := int(toFloat64(args[0]))
	return randString(n, numericChars)
}

// dslRandInt generates a random integer between min and max (inclusive).
func dslRandInt(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 2 {
		nBig, err := rand.Int(rand.Reader, big.NewInt(1<<31))
		if err != nil {
			return float64(0)
		}
		return float64(nBig.Int64())
	}
	min := int64(toFloat64(args[0]))
	max := int64(toFloat64(args[1]))
	if max <= min {
		return float64(min)
	}
	diff := max - min + 1
	nBig, err := rand.Int(rand.Reader, big.NewInt(diff))
	if err != nil {
		return float64(min)
	}
	return float64(min + nBig.Int64())
}

// dslRandBase generates a random base36 string of length n.
func dslRandBase(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	n := int(toFloat64(args[0]))
	return randString(n, base36Chars)
}

// dslRandChar generates a random single character from the given charset.
func dslRandChar(args []interface{}, ctx map[string]interface{}) interface{} {
	charset := alphanumericChars
	if len(args) >= 1 {
		charset = fmt.Sprintf("%v", args[0])
	}
	if len(charset) == 0 {
		return ""
	}
	return string(charset[mathrand.Intn(len(charset))])
}

// dslRandIP generates a random IPv4 address string.
func dslRandIP(args []interface{}, ctx map[string]interface{}) interface{} {
	return fmt.Sprintf("%d.%d.%d.%d",
		mathrand.Intn(256),
		mathrand.Intn(256),
		mathrand.Intn(256),
		mathrand.Intn(256),
	)
}

// Version comparison

// dslCompareVersions compares two versions with an operator.
// Usage: compare_versions(version, operator, constraint) e.g. compare_versions("1.2.3", ">=", "1.0.0")
func dslCompareVersions(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 3 {
		return false
	}
	v1Str := fmt.Sprintf("%v", args[0])
	op := fmt.Sprintf("%v", args[1])
	v2Str := fmt.Sprintf("%v", args[2])

	cmp := compareVersionStrings(v1Str, v2Str)
	switch op {
	case "==", "=":
		return cmp == 0
	case "!=":
		return cmp != 0
	case ">":
		return cmp > 0
	case "<":
		return cmp < 0
	case ">=":
		return cmp >= 0
	case "<=":
		return cmp <= 0
	}
	return false
}

// compareVersionStrings compares two version strings, returning -1, 0, or 1.
func compareVersionStrings(v1, v2 string) int {
	// Strip leading 'v'
	v1 = strings.TrimPrefix(v1, "v")
	v2 = strings.TrimPrefix(v2, "v")

	// Split on '-' to handle pre-release
	v1Parts := strings.SplitN(v1, "-", 2)
	v2Parts := strings.SplitN(v2, "-", 2)

	segs1 := strings.Split(v1Parts[0], ".")
	segs2 := strings.Split(v2Parts[0], ".")

	maxLen := len(segs1)
	if len(segs2) > maxLen {
		maxLen = len(segs2)
	}

	for i := 0; i < maxLen; i++ {
		var n1, n2 int
		if i < len(segs1) {
			n1, _ = strconv.Atoi(segs1[i])
		}
		if i < len(segs2) {
			n2, _ = strconv.Atoi(segs2[i])
		}
		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}
	}

	// Handle pre-release: version without pre-release is greater
	hasPre1 := len(v1Parts) > 1
	hasPre2 := len(v2Parts) > 1
	if hasPre1 && !hasPre2 {
		return -1
	}
	if !hasPre1 && hasPre2 {
		return 1
	}
	return 0
}

// Time functions

// dslUnixTime returns the current Unix timestamp in seconds.
func dslUnixTime(args []interface{}, ctx map[string]interface{}) interface{} {
	return float64(time.Now().Unix())
}

// dslToUnixTime converts a time string to Unix timestamp.
func dslToUnixTime(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return float64(0)
	}
	str := fmt.Sprintf("%v", args[0])
	layout := time.RFC3339
	if len(args) >= 2 {
		layout = strftimeToGoLayout(fmt.Sprintf("%v", args[1]))
	}
	t, err := time.Parse(layout, str)
	if err != nil {
		return float64(0)
	}
	return float64(t.Unix())
}

// dslDateTime formats the current time (or a given Unix timestamp) using a format string.
func dslDateTime(args []interface{}, ctx map[string]interface{}) interface{} {
	format := "2006-01-02 15:04:05"
	t := time.Now()

	if len(args) >= 1 {
		// First arg can be format string or unix timestamp
		switch v := args[0].(type) {
		case float64:
			t = time.Unix(int64(v), 0)
		case int64:
			t = time.Unix(v, 0)
		case string:
			format = strftimeToGoLayout(v)
		}
	}
	if len(args) >= 2 {
		ts := toFloat64(args[1])
		t = time.Unix(int64(ts), 0)
	}
	return t.Format(format)
}

// dslWaitFor sleeps for n seconds (no-op for safety in tests, minimal delay).
func dslWaitFor(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return nil
	}
	n := toFloat64(args[0])
	if n > 0 && n <= 5 {
		time.Sleep(time.Duration(n) * time.Second)
	}
	return nil
}

// strftimeReplacer converts strftime format directives to Go time layout tokens.
var strftimeReplacer = strings.NewReplacer(
	"%Y", "2006",
	"%m", "01",
	"%d", "02",
	"%H", "15",
	"%M", "04",
	"%S", "05",
	"%Z", "MST",
	"%z", "-0700",
	"%y", "06",
	"%b", "Jan",
	"%B", "January",
	"%a", "Mon",
	"%A", "Monday",
)

// strftimeToGoLayout converts a strftime format string to Go layout.
func strftimeToGoLayout(format string) string {
	return strftimeReplacer.Replace(format)
}

