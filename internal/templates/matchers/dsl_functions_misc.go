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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

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

// dslParseIntBase returns a DSLFunction that parses a string in the given base and returns
// the decimal value as float64. For base 16 the optional "0x" prefix is stripped first.
func dslParseIntBase(base int) DSLFunction {
	return func(args []interface{}, ctx map[string]interface{}) interface{} {
		if len(args) < 1 {
			return float64(0)
		}
		s := fmt.Sprintf("%v", args[0])
		if base == 16 {
			s = strings.TrimPrefix(s, "0x")
		}
		n, err := strconv.ParseInt(s, base, 64)
		if err != nil {
			return float64(0)
		}
		return float64(n)
	}
}

// dslHexToDec is kept as a named alias for registration clarity.
var dslHexToDec = dslParseIntBase(16)

// dslBinToDec is kept as a named alias for registration clarity.
var dslBinToDec = dslParseIntBase(2)

// dslOctToDec is kept as a named alias for registration clarity.
var dslOctToDec = dslParseIntBase(8)

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
