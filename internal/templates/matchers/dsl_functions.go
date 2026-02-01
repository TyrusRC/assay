package matchers

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// String functions

func dslStartsWith(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 2 {
		return false
	}
	str := fmt.Sprintf("%v", args[0])
	prefix := fmt.Sprintf("%v", args[1])
	return strings.HasPrefix(str, prefix)
}

func dslEndsWith(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 2 {
		return false
	}
	str := fmt.Sprintf("%v", args[0])
	suffix := fmt.Sprintf("%v", args[1])
	return strings.HasSuffix(str, suffix)
}

func dslToUpper(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	return strings.ToUpper(fmt.Sprintf("%v", args[0]))
}

func dslToLower(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	return strings.ToLower(fmt.Sprintf("%v", args[0]))
}

func dslTrim(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", args[0]))
}

func dslReplace(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 3 {
		return ""
	}
	str := fmt.Sprintf("%v", args[0])
	old := fmt.Sprintf("%v", args[1])
	new := fmt.Sprintf("%v", args[2])
	return strings.ReplaceAll(str, old, new)
}

func dslSplit(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 2 {
		return []string{}
	}
	str := fmt.Sprintf("%v", args[0])
	sep := fmt.Sprintf("%v", args[1])
	return strings.Split(str, sep)
}

func dslContains(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 2 {
		return false
	}

	// Handle list contains
	if list, ok := args[0].([]string); ok {
		item := fmt.Sprintf("%v", args[1])
		for _, v := range list {
			if v == item {
				return true
			}
		}
		return false
	}

	// Handle string contains
	haystack := fmt.Sprintf("%v", args[0])
	needle := fmt.Sprintf("%v", args[1])
	return strings.Contains(haystack, needle)
}

func dslLen(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return 0
	}

	switch v := args[0].(type) {
	case string:
		return float64(len(v))
	case []string:
		return float64(len(v))
	case []interface{}:
		return float64(len(v))
	default:
		return float64(len(fmt.Sprintf("%v", v)))
	}
}

// Encoding functions

func dslBase64Encode(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	str := fmt.Sprintf("%v", args[0])
	return base64.StdEncoding.EncodeToString([]byte(str))
}

func dslBase64Decode(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	str := fmt.Sprintf("%v", args[0])
	decoded, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return ""
	}
	return string(decoded)
}

func dslURLEncode(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	str := fmt.Sprintf("%v", args[0])
	return url.QueryEscape(str)
}

func dslURLDecode(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	str := fmt.Sprintf("%v", args[0])
	decoded, err := url.QueryUnescape(str)
	if err != nil {
		return str
	}
	return decoded
}

func dslHTMLEncode(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	str := fmt.Sprintf("%v", args[0])
	return html.EscapeString(str)
}

func dslHTMLDecode(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	str := fmt.Sprintf("%v", args[0])
	return html.UnescapeString(str)
}

// Hash functions

func dslMD5(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	str := fmt.Sprintf("%v", args[0])
	hash := md5.Sum([]byte(str))
	return hex.EncodeToString(hash[:])
}

func dslSHA1(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	str := fmt.Sprintf("%v", args[0])
	hash := sha1.Sum([]byte(str))
	return hex.EncodeToString(hash[:])
}

func dslSHA256(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 1 {
		return ""
	}
	str := fmt.Sprintf("%v", args[0])
	hash := sha256.Sum256([]byte(str))
	return hex.EncodeToString(hash[:])
}

// List functions

func dslJoin(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 2 {
		return ""
	}

	sep := fmt.Sprintf("%v", args[1])

	switch list := args[0].(type) {
	case []string:
		return strings.Join(list, sep)
	case []interface{}:
		strs := make([]string, len(list))
		for i, v := range list {
			strs[i] = fmt.Sprintf("%v", v)
		}
		return strings.Join(strs, sep)
	default:
		return ""
	}
}

// Regex function

var (
	dslRegexCache   = make(map[string]*regexp.Regexp)
	dslRegexCacheMu sync.RWMutex
)

func dslRegexMatch(args []interface{}, ctx map[string]interface{}) interface{} {
	if len(args) < 2 {
		return false
	}
	str := fmt.Sprintf("%v", args[0])
	pattern := fmt.Sprintf("%v", args[1])

	dslRegexCacheMu.RLock()
	re, ok := dslRegexCache[pattern]
	dslRegexCacheMu.RUnlock()

	if !ok {
		var err error
		re, err = regexp.Compile(pattern)
		if err != nil {
			return false
		}
		dslRegexCacheMu.Lock()
		dslRegexCache[pattern] = re
		dslRegexCacheMu.Unlock()
	}

	return re.MatchString(str)
}
