package matchers

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"hash/fnv"
	"regexp"
	"strings"
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
	count := int(toFloat64(args[1]))
	if count < 0 {
		count = 0
	}
	if count > 10000 { // Prevent memory exhaustion
		count = 10000
	}
	return strings.Repeat(str, count)
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

// dslHMAC computes an HMAC of the data with the given key using the specified algorithm.
// Supported algorithms: sha1, sha256 (default).
func dslHMAC(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 3 {
		return ""
	}
	algo := fmt.Sprintf("%v", args[0])
	key := fmt.Sprintf("%v", args[1])
	data := fmt.Sprintf("%v", args[2])

	var mac hash.Hash
	switch strings.ToLower(algo) {
	case "sha1":
		mac = hmac.New(sha1.New, []byte(key))
	case "sha256":
		mac = hmac.New(sha256.New, []byte(key))
	default:
		mac = hmac.New(sha256.New, []byte(key))
	}
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}
