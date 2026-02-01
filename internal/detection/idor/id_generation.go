package idor

import (
	"encoding/base64"
	"encoding/hex"
	"strconv"

	"github.com/google/uuid"
)

// generateManipulatedIDs generates test IDs based on the original ID type.
func (d *Detector) generateManipulatedIDs(originalID string, idType IDType) []string {
	var ids []string

	switch idType {
	case IDTypeNumeric:
		ids = d.generateNumericIDs(originalID)
	case IDTypeUUID:
		ids = d.generateUUIDs(originalID)
	case IDTypeBase64:
		ids = d.generateBase64IDs(originalID)
	case IDTypeHex:
		ids = d.generateHexIDs(originalID)
	default:
		ids = d.generateAlphanumericIDs(originalID)
	}

	return ids
}

// generateNumericIDs generates test numeric IDs.
func (d *Detector) generateNumericIDs(originalID string) []string {
	var ids []string

	num, err := strconv.ParseInt(originalID, 10, 64)
	if err != nil {
		return ids
	}

	// Increment and decrement
	if num > 0 {
		ids = append(ids, strconv.FormatInt(num-1, 10))
	}
	ids = append(ids, strconv.FormatInt(num+1, 10))

	// Common IDs
	commonIDs := []int64{0, 1, 2, 100, 1000}
	for _, cid := range commonIDs {
		if cid != num {
			ids = append(ids, strconv.FormatInt(cid, 10))
		}
	}

	// Random nearby IDs
	if num > 10 {
		ids = append(ids, strconv.FormatInt(num-10, 10))
	}
	ids = append(ids, strconv.FormatInt(num+10, 10))

	return ids
}

// generateUUIDs generates test UUIDs.
func (d *Detector) generateUUIDs(originalID string) []string {
	var ids []string

	// Generate random UUIDs
	for i := 0; i < 3; i++ {
		ids = append(ids, uuid.New().String())
	}

	// Nil UUID
	ids = append(ids, "00000000-0000-0000-0000-000000000000")

	// Modified version of original (change last segment)
	if len(originalID) >= 36 {
		modified := originalID[:24] + "000000000000"
		ids = append(ids, modified)
	}

	return ids
}

// generateBase64IDs generates test base64-encoded IDs.
func (d *Detector) generateBase64IDs(originalID string) []string {
	var ids []string

	// Try to decode and manipulate
	decoded, err := base64.StdEncoding.DecodeString(originalID)
	if err != nil {
		return ids
	}

	decodedStr := string(decoded)

	// Try to find and manipulate numeric parts
	matches := d.numPattern.FindStringSubmatchIndex(decodedStr)
	if matches != nil {
		// Extract the number
		numStr := decodedStr[matches[2]:matches[3]]
		num, err := strconv.ParseInt(numStr, 10, 64)
		if err == nil {
			// Generate variations
			variations := []int64{num - 1, num + 1, 0, 1, 2}
			for _, v := range variations {
				if v != num {
					modified := decodedStr[:matches[2]] + strconv.FormatInt(v, 10) + decodedStr[matches[3]:]
					ids = append(ids, base64.StdEncoding.EncodeToString([]byte(modified)))
				}
			}
		}
	}

	return ids
}

// generateHexIDs generates test hex-encoded IDs.
func (d *Detector) generateHexIDs(originalID string) []string {
	var ids []string

	// Try to decode and manipulate
	decoded, err := hex.DecodeString(originalID)
	if err != nil {
		return ids
	}

	decodedStr := string(decoded)

	// Try to find and manipulate numeric parts
	matches := d.numPattern.FindStringSubmatchIndex(decodedStr)
	if matches != nil {
		numStr := decodedStr[matches[2]:matches[3]]
		num, err := strconv.ParseInt(numStr, 10, 64)
		if err == nil {
			variations := []int64{num - 1, num + 1, 0, 1, 2}
			for _, v := range variations {
				if v != num {
					modified := decodedStr[:matches[2]] + strconv.FormatInt(v, 10) + decodedStr[matches[3]:]
					ids = append(ids, hex.EncodeToString([]byte(modified)))
				}
			}
		}
	}

	return ids
}

// generateAlphanumericIDs generates test alphanumeric IDs.
func (d *Detector) generateAlphanumericIDs(originalID string) []string {
	var ids []string

	// Try common variations
	ids = append(ids, "admin", "test", "user", "1", "0")

	// Try modifying numeric suffix
	if matches := d.numSuffix.FindStringSubmatch(originalID); matches != nil {
		prefix := matches[1]
		numStr := matches[2]
		num, err := strconv.ParseInt(numStr, 10, 64)
		if err == nil {
			if num > 0 {
				ids = append(ids, prefix+strconv.FormatInt(num-1, 10))
			}
			ids = append(ids, prefix+strconv.FormatInt(num+1, 10))
		}
	}

	return ids
}
