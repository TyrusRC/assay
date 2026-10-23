package iast

import (
	"regexp"
	"strings"

	"github.com/google/uuid"
)

const (
	MarkerPrefix = "ASSAY_TAINT_"
	MarkerSuffix = "_TAINT_ASSAY"
)

var markerIDRe = regexp.MustCompile(`ASSAY_TAINT_([a-f0-9]{8})_`)

// GenerateMarker returns a fresh marker ID and the full marker string
// for a given sink type.
func GenerateMarker(sinkType string) (id, payload string) {
	id = uuid.New().String()[:8]
	payload = MarkerPrefix + id + "_" + sinkType + MarkerSuffix
	return id, payload
}

// WrapPayload wraps an existing DAST payload with a taint marker so
// the sensor can detect it at the sink and correlate back to markerID.
func WrapPayload(originalPayload, markerID, sinkType string) string {
	return MarkerPrefix + markerID + "_" + sinkType + "_" + originalPayload + MarkerSuffix
}

// IsMarker returns true when value contains the taint marker pair.
func IsMarker(value string) bool {
	return strings.Contains(value, MarkerPrefix) && strings.Contains(value, MarkerSuffix)
}

// ExtractMarkerID returns the 8-hex-char marker ID embedded in value,
// or an empty string when no marker is present.
func ExtractMarkerID(value string) string {
	m := markerIDRe.FindStringSubmatch(value)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}
