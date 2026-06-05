// Package bac detects broken access control at the function level: cases where
// a resource or action that is legitimately served to a privileged principal
// is also served, with equivalent content, to a lower-privileged or anonymous
// principal. This is the class the OWASP API Top 10 calls Broken Function Level
// Authorization (API5) and generalizes the object-level (IDOR/BOLA) check to
// every discovered endpoint, in the spirit of automatic black-box BAC
// inference (cf. BACScan, CCS'25).
//
// Detection is differential and conservative: each endpoint is requested as a
// privileged baseline and as one or more other principals; an endpoint is
// flagged only when a lower principal receives a success response that is
// content-equivalent to the privileged one.
package bac

const (
	// KindUnauthenticated means an anonymous principal reached privileged content.
	KindUnauthenticated = "unauthenticated-access"
	// KindCrossUser means a different authenticated user reached the content.
	KindCrossUser = "cross-user-access"
)

// minBodyForLengthHeuristic is the smallest body size for which a near-equal
// length (rather than an exact hash match) is trusted as an equivalence signal.
// Below this, tiny bodies like "OK" would collide by length alone.
const minBodyForLengthHeuristic = 64

// lengthTolerance is the byte delta within which two larger bodies are treated
// as equivalent, absorbing per-request noise (CSRF tokens, timestamps).
const lengthTolerance = 16

// AccessObservation records how one principal experienced an endpoint.
type AccessObservation struct {
	// Principal identifies who made the request (e.g. "user-a", "anonymous").
	Principal string
	// BodyHash is a stable hash of the response body.
	BodyHash string
	// Status is the HTTP status code.
	Status int
	// BodyLen is the response body length in bytes.
	BodyLen int
}

// Verdict is the access-control classification for one endpoint.
type Verdict struct {
	// Kind is the violation kind when Broken is true.
	Kind string
	// Detail is a human-readable explanation.
	Detail string
	// Offender is the principal that improperly gained access.
	Offender string
	// Broken reports whether broken access control was found.
	Broken bool
}

// isSuccess reports whether a status code indicates the content was served.
func isSuccess(status int) bool {
	return status >= 200 && status < 300
}

// equivalent reports whether an observation's content matches the privileged
// baseline closely enough to conclude the same resource was served.
func equivalent(priv, other AccessObservation) bool {
	if !isSuccess(other.Status) {
		return false
	}
	if other.BodyHash == priv.BodyHash {
		return true
	}
	// Larger bodies of near-equal length are treated as the same resource with
	// per-request noise; tiny bodies require an exact hash match.
	if priv.BodyLen >= minBodyForLengthHeuristic && other.BodyLen >= minBodyForLengthHeuristic {
		return absInt(priv.BodyLen-other.BodyLen) <= lengthTolerance
	}
	return false
}

// Classify compares a privileged baseline against other principals' access and
// returns the access-control verdict. The privileged observation must itself be
// a success, or there is no baseline to leak.
func Classify(privileged AccessObservation, others []AccessObservation) Verdict {
	if !isSuccess(privileged.Status) {
		return Verdict{}
	}
	for _, o := range others {
		if !equivalent(privileged, o) {
			continue
		}
		kind := KindCrossUser
		if isAnonymous(o.Principal) {
			kind = KindUnauthenticated
		}
		return Verdict{
			Broken:   true,
			Kind:     kind,
			Offender: o.Principal,
			Detail: "principal " + o.Principal + " received content equivalent to the privileged " +
				privileged.Principal + " response (status " + itoa(o.Status) + ")",
		}
	}
	return Verdict{}
}

func isAnonymous(principal string) bool {
	return principal == "anonymous" || principal == "" || principal == "anon"
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
