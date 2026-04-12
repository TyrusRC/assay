package matchers

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"math/big"
	mathrand "math/rand"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// registerExtendedFunctions registers all extended DSL functions for nuclei compatibility.
func (e *DSLEngine) registerExtendedFunctions() {
	// Snake_case aliases for existing functions
	e.functions["starts_with"] = dslStartsWith
	e.functions["ends_with"] = dslEndsWith
	e.functions["to_upper"] = dslToUpper
	e.functions["to_lower"] = dslToLower

	// String matching
	e.functions["contains_all"] = dslContainsAll
	e.functions["contains_any"] = dslContainsAny
	e.functions["regex"] = dslRegex
	e.functions["regex_any"] = dslRegexAny
	e.functions["regex_all"] = dslRegexAll
	e.functions["equals_any"] = dslEqualsAny
	e.functions["line_starts_with"] = dslLineStartsWith
	e.functions["line_ends_with"] = dslLineEndsWith

	// String manipulation
	e.functions["concat"] = dslConcat
	e.functions["repeat"] = dslRepeat
	e.functions["reverse"] = dslReverse
	e.functions["remove_bad_chars"] = dslRemoveBadChars
	e.functions["trim_left"] = dslTrimLeft
	e.functions["trim_right"] = dslTrimRight
	e.functions["trim_space"] = dslTrimSpace
	e.functions["trim_prefix"] = dslTrimPrefix
	e.functions["trim_suffix"] = dslTrimSuffix
	e.functions["replace_regex"] = dslReplaceRegex

	// Encoding
	e.functions["hex_encode"] = dslHexEncode
	e.functions["hex_decode"] = dslHexDecode
	e.functions["base64_py"] = dslBase64Encode // alias

	// Hash
	e.functions["mmh3"] = dslMMH3
	e.functions["hmac"] = dslHMAC

	// Random
	e.functions["rand_text_alpha"] = dslRandTextAlpha
	e.functions["rand_text_alphanumeric"] = dslRandTextAlphanumeric
	e.functions["rand_text_numeric"] = dslRandTextNumeric
	e.functions["rand_int"] = dslRandInt
	e.functions["rand_base"] = dslRandBase
	e.functions["rand_char"] = dslRandChar
	e.functions["rand_ip"] = dslRandIP

	// Version comparison
	e.functions["compare_versions"] = dslCompareVersions

	// Time
	e.functions["unix_time"] = dslUnixTime
	e.functions["to_unix_time"] = dslToUnixTime
	e.functions["date_time"] = dslDateTime
	e.functions["wait_for"] = dslWaitFor

	// Compression
	e.functions["gzip"] = dslGzip
	e.functions["gzip_decode"] = dslGzipDecode
	e.functions["zlib"] = dslZlib
	e.functions["zlib_decode"] = dslZlibDecode

	// Encryption
	e.functions["aes_gcm"] = dslAESGCM

	// Number conversion
	e.functions["dec_to_hex"] = dslDecToHex
	e.functions["hex_to_dec"] = dslHexToDec
	e.functions["bin_to_dec"] = dslBinToDec
	e.functions["oct_to_dec"] = dslOctToDec

	// Network
	e.functions["resolve"] = dslResolve
	e.functions["ip_format"] = dslIPFormat

	// JSON
	e.functions["json_minify"] = dslJSONMinify
	e.functions["json_prettify"] = dslJSONPrettify
	e.functions["generate_jwt"] = dslGenerateJWT

	// Deserialization (placeholder markers)
	e.functions["generate_java_gadget"] = dslGenerateJavaGadget
	e.functions["generate_dotnet_gadget"] = dslGenerateDotnetGadget

	// Debug
	e.functions["print_debug"] = dslPrintDebug
}

// getRegex returns a compiled regex from cache, compiling if necessary.
func getRegex(pattern string) (*regexp.Regexp, error) {
	dslRegexCacheMu.RLock()
	re, ok := dslRegexCache[pattern]
	dslRegexCacheMu.RUnlock()
	if ok {
		return re, nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	dslRegexCacheMu.Lock()
	dslRegexCache[pattern] = re
	dslRegexCacheMu.Unlock()
	return re, nil
}

// String matching functions

// dslContainsAll returns true if the string contains all of the provided substrings.
func dslContainsAll(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 2 {
		return false
	}
	haystack := fmt.Sprintf("%v", args[0])
	for _, arg := range args[1:] {
		needle := fmt.Sprintf("%v", arg)
		if !strings.Contains(haystack, needle) {
			return false
		}
	}
	return true
}

// dslContainsAny returns true if the string contains any of the provided substrings.
func dslContainsAny(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 2 {
		return false
	}
	haystack := fmt.Sprintf("%v", args[0])
	for _, arg := range args[1:] {
		needle := fmt.Sprintf("%v", arg)
		if strings.Contains(haystack, needle) {
			return true
		}
	}
	return false
}

// dslRegex matches a regex pattern against text (pattern, text order - nuclei style).
func dslRegex(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 2 {
		return false
	}
	pattern := fmt.Sprintf("%v", args[0])
	text := fmt.Sprintf("%v", args[1])
	re, err := getRegex(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(text)
}

// dslRegexAny returns true if any of the patterns match the text.
func dslRegexAny(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 2 {
		return false
	}
	text := fmt.Sprintf("%v", args[0])
	for _, arg := range args[1:] {
		pattern := fmt.Sprintf("%v", arg)
		re, err := getRegex(pattern)
		if err != nil {
			continue
		}
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

// dslRegexAll returns true if all of the patterns match the text.
func dslRegexAll(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 2 {
		return false
	}
	text := fmt.Sprintf("%v", args[0])
	for _, arg := range args[1:] {
		pattern := fmt.Sprintf("%v", arg)
		re, err := getRegex(pattern)
		if err != nil {
			return false
		}
		if !re.MatchString(text) {
			return false
		}
	}
	return true
}

// dslEqualsAny returns true if the value equals any of the provided values.
func dslEqualsAny(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 2 {
		return false
	}
	value := fmt.Sprintf("%v", args[0])
	for _, arg := range args[1:] {
		if fmt.Sprintf("%v", arg) == value {
			return true
		}
	}
	return false
}

// dslLineStartsWith returns true if any line in the text starts with the prefix.
func dslLineStartsWith(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 2 {
		return false
	}
	text := fmt.Sprintf("%v", args[0])
	prefix := fmt.Sprintf("%v", args[1])
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

// dslLineEndsWith returns true if any line in the text ends with the suffix.
func dslLineEndsWith(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 2 {
		return false
	}
	text := fmt.Sprintf("%v", args[0])
	suffix := fmt.Sprintf("%v", args[1])
	for _, line := range strings.Split(text, "\n") {
		if strings.HasSuffix(strings.TrimRight(line, "\r"), suffix) {
			return true
		}
	}
	return false
}

// String manipulation functions

// dslConcat concatenates all arguments as strings.
func dslConcat(args []interface{}, ctx map[string]interface{}) interface{} {
	var sb strings.Builder
	for _, arg := range args {
		sb.WriteString(fmt.Sprintf("%v", arg))
	}
	return sb.String()
}

// dslRepeat repeats a string n times.
func dslRepeat(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 2 {
		return ""
	}
	str := fmt.Sprintf("%v", args[0])
	n := int(toFloat64(args[1]))
	if n < 0 {
		return ""
	}
	return strings.Repeat(str, n)
}

// dslReverse reverses a string.
func dslReverse(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	str := fmt.Sprintf("%v", args[0])
	runes := []rune(str)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// dslRemoveBadChars removes all characters in the bad chars set from the string.
func dslRemoveBadChars(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 2 {
		return ""
	}
	str := fmt.Sprintf("%v", args[0])
	badChars := fmt.Sprintf("%v", args[1])
	result := strings.Map(func(r rune) rune {
		if strings.ContainsRune(badChars, r) {
			return -1
		}
		return r
	}, str)
	return result
}

// dslTrimLeft trims characters from the left of a string.
func dslTrimLeft(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 2 {
		return ""
	}
	str := fmt.Sprintf("%v", args[0])
	cutset := fmt.Sprintf("%v", args[1])
	return strings.TrimLeft(str, cutset)
}

// dslTrimRight trims characters from the right of a string.
func dslTrimRight(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 2 {
		return ""
	}
	str := fmt.Sprintf("%v", args[0])
	cutset := fmt.Sprintf("%v", args[1])
	return strings.TrimRight(str, cutset)
}

// dslTrimSpace trims whitespace from both ends of a string.
func dslTrimSpace(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", args[0]))
}

// dslTrimPrefix removes a prefix from a string.
func dslTrimPrefix(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 2 {
		return ""
	}
	str := fmt.Sprintf("%v", args[0])
	prefix := fmt.Sprintf("%v", args[1])
	return strings.TrimPrefix(str, prefix)
}

// dslTrimSuffix removes a suffix from a string.
func dslTrimSuffix(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 2 {
		return ""
	}
	str := fmt.Sprintf("%v", args[0])
	suffix := fmt.Sprintf("%v", args[1])
	return strings.TrimSuffix(str, suffix)
}

// dslReplaceRegex replaces all regex matches with a replacement string.
func dslReplaceRegex(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 3 {
		return ""
	}
	str := fmt.Sprintf("%v", args[0])
	pattern := fmt.Sprintf("%v", args[1])
	replacement := fmt.Sprintf("%v", args[2])
	re, err := getRegex(pattern)
	if err != nil {
		return str
	}
	return re.ReplaceAllString(str, replacement)
}

// Encoding functions

// dslHexEncode encodes a string to hexadecimal.
func dslHexEncode(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	str := fmt.Sprintf("%v", args[0])
	return hex.EncodeToString([]byte(str))
}

// dslHexDecode decodes a hexadecimal string.
func dslHexDecode(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	str := fmt.Sprintf("%v", args[0])
	decoded, err := hex.DecodeString(str)
	if err != nil {
		return ""
	}
	return string(decoded)
}

// Hash functions

// dslMMH3 computes a MurmurHash3-like hash using FNV-1a as approximation.
func dslMMH3(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return float64(0)
	}
	str := fmt.Sprintf("%v", args[0])
	h := fnv.New32a()
	_, err := h.Write([]byte(str))
	if err != nil {
		return float64(0)
	}
	return float64(int32(h.Sum32()))
}

// dslHMAC computes an HMAC-SHA256 of the data with the given key.
func dslHMAC(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 3 {
		return ""
	}
	// args: algorithm, data, key
	data := fmt.Sprintf("%v", args[1])
	key := fmt.Sprintf("%v", args[2])
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

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

// strftimeToGoLayout converts a strftime format string to Go layout.
func strftimeToGoLayout(format string) string {
	replacer := strings.NewReplacer(
		"%Y", "2006",
		"%m", "01",
		"%d", "02",
		"%H", "15",
		"%M", "04",
		"%S", "05",
		"%Z", "MST",
		"%z", "-0700",
	)
	return replacer.Replace(format)
}

// Compression functions

// dslGzip compresses data using gzip.
func dslGzip(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	data := []byte(fmt.Sprintf("%v", args[0]))
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return ""
	}
	if err := w.Close(); err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// dslGzipDecode decompresses gzip-encoded (base64) data.
func dslGzipDecode(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	encoded := fmt.Sprintf("%v", args[0])
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// Try raw bytes
		data = []byte(encoded)
	}
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return ""
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return ""
	}
	return string(out)
}

// dslZlib compresses data using zlib.
func dslZlib(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	data := []byte(fmt.Sprintf("%v", args[0]))
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return ""
	}
	if err := w.Close(); err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// dslZlibDecode decompresses zlib-encoded (base64) data.
func dslZlibDecode(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	encoded := fmt.Sprintf("%v", args[0])
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		data = []byte(encoded)
	}
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return ""
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return ""
	}
	return string(out)
}

// Encryption functions

// dslAESGCM encrypts data using AES-GCM with the given key.
// Returns base64-encoded nonce+ciphertext.
func dslAESGCM(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 2 {
		return ""
	}
	keyStr := fmt.Sprintf("%v", args[0])
	plaintext := []byte(fmt.Sprintf("%v", args[1]))

	// Pad or truncate key to 32 bytes
	key := make([]byte, 32)
	copy(key, []byte(keyStr))

	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return ""
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

// Number conversion functions

// dslDecToHex converts a decimal number to hexadecimal string.
func dslDecToHex(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	n := int64(toFloat64(args[0]))
	return fmt.Sprintf("%x", n)
}

// dslHexToDec converts a hexadecimal string to decimal number.
func dslHexToDec(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return float64(0)
	}
	str := strings.TrimPrefix(fmt.Sprintf("%v", args[0]), "0x")
	n, err := strconv.ParseInt(str, 16, 64)
	if err != nil {
		return float64(0)
	}
	return float64(n)
}

// dslBinToDec converts a binary string to decimal number.
func dslBinToDec(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return float64(0)
	}
	str := fmt.Sprintf("%v", args[0])
	n, err := strconv.ParseInt(str, 2, 64)
	if err != nil {
		return float64(0)
	}
	return float64(n)
}

// dslOctToDec converts an octal string to decimal number.
func dslOctToDec(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return float64(0)
	}
	str := fmt.Sprintf("%v", args[0])
	n, err := strconv.ParseInt(str, 8, 64)
	if err != nil {
		return float64(0)
	}
	return float64(n)
}

// Network functions

// dslResolve performs a DNS lookup and returns the first IP address.
func dslResolve(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	host := fmt.Sprintf("%v", args[0])
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return ""
	}
	return addrs[0]
}

// dslIPFormat converts an IP address to different formats.
// args: ip, format (1=decimal, 2=hex, 3=octal, 4=dotted-hex)
func dslIPFormat(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 2 {
		return ""
	}
	ipStr := fmt.Sprintf("%v", args[0])
	format := int(toFloat64(args[1]))
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	ip = ip.To4()
	if ip == nil {
		return ""
	}
	val := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	switch format {
	case 1:
		return fmt.Sprintf("%d", val)
	case 2:
		return fmt.Sprintf("0x%08x", val)
	case 3:
		return fmt.Sprintf("0%o", val)
	case 4:
		return fmt.Sprintf("0x%02x.0x%02x.0x%02x.0x%02x", ip[0], ip[1], ip[2], ip[3])
	}
	return fmt.Sprintf("%d", val)
}

// JSON functions

// dslJSONMinify minifies a JSON string.
func dslJSONMinify(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	str := fmt.Sprintf("%v", args[0])
	var v interface{}
	if err := json.Unmarshal([]byte(str), &v); err != nil {
		return str
	}
	minified, err := json.Marshal(v)
	if err != nil {
		return str
	}
	return string(minified)
}

// dslJSONPrettify prettifies a JSON string.
func dslJSONPrettify(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	str := fmt.Sprintf("%v", args[0])
	var v interface{}
	if err := json.Unmarshal([]byte(str), &v); err != nil {
		return str
	}
	pretty, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return str
	}
	return string(pretty)
}

// dslGenerateJWT generates a simple JWT token (HS256) from header, payload, and secret.
func dslGenerateJWT(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 3 {
		return ""
	}
	header := fmt.Sprintf("%v", args[0])
	payload := fmt.Sprintf("%v", args[1])
	secret := fmt.Sprintf("%v", args[2])

	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(header))
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signingInput := headerB64 + "." + payloadB64

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig
}

// Deserialization placeholder functions

// dslGenerateJavaGadget returns a placeholder marker for Java deserialization gadgets.
func dslGenerateJavaGadget(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return "JAVA_GADGET_PLACEHOLDER"
	}
	gadgetType := fmt.Sprintf("%v", args[0])
	return fmt.Sprintf("JAVA_GADGET_%s_PLACEHOLDER", strings.ToUpper(gadgetType))
}

// dslGenerateDotnetGadget returns a placeholder marker for .NET deserialization gadgets.
func dslGenerateDotnetGadget(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return "DOTNET_GADGET_PLACEHOLDER"
	}
	gadgetType := fmt.Sprintf("%v", args[0])
	return fmt.Sprintf("DOTNET_GADGET_%s_PLACEHOLDER", strings.ToUpper(gadgetType))
}

// Debug functions

// dslPrintDebug is a no-op debug function for nuclei template compatibility.
func dslPrintDebug(args []interface{}, ctx map[string]interface{}) interface{} {
	return nil
}
