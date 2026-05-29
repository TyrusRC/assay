// Package webauthn provides payloads for WebAuthn / passkey
// registration and authentication flow audits. Targets the relying-party
// (server) side: the browser-side WebAuthn implementation is fixed by
// the spec, but the server's verification logic is application code and
// has accumulated a well-known set of bugs (origin not pinned, RP-ID
// substring vs. equality, signature counter regression silently
// accepted, attestation parsing optional, credential ID reuse across
// users).
//
// Mirrors the FIDO Alliance "FIDO2 Server Test Tools" attack surface
// plus the WebAuthn Adventures (Hava Singh / NCC Group 2022)
// credential-substitution chapter.
package webauthn

// Class identifies the WebAuthn check class.
type Class string

const (
	ClassOriginSpoof        Class = "origin_spoof"
	ClassRPIDMismatch       Class = "rp_id_mismatch"
	ClassAttestationBypass  Class = "attestation_bypass"
	ClassCounterRegression  Class = "counter_regression"
	ClassCredentialIDReuse  Class = "credential_id_reuse"
	ClassUserVerification   Class = "user_verification_bypass"
	ClassChallengeReuse     Class = "challenge_reuse"
	ClassClientDataInject   Class = "client_data_injection"
)

// Impact classifies the resulting capability of a successful exploit.
type Impact string

const (
	ImpactAccountTakeover Impact = "account_takeover"
	ImpactAuthBypass      Impact = "auth_bypass"
	ImpactInfoLeak        Impact = "info_leak"
	ImpactRegistration    Impact = "credential_substitution"
)

// Phase identifies which WebAuthn ceremony the payload targets.
type Phase string

const (
	PhaseRegistration   Phase = "registration"     // navigator.credentials.create()
	PhaseAuthentication Phase = "authentication"   // navigator.credentials.get()
	PhaseBoth           Phase = "both"
)

// Payload represents a WebAuthn flow-level attack payload.
type Payload struct {
	Class       Class
	Phase       Phase
	Impact      Impact
	Description string
	// MutationHint instructs the scanner-side runner what to mutate in
	// the standard WebAuthn JSON envelope. Most attacks are at the
	// `clientDataJSON` (base64url-encoded JSON) level — the runner
	// base64-decodes, mutates the indicated field, re-encodes.
	MutationHint string
	// ExpectedReject is the symptom that proves the server REJECTED
	// the payload correctly (i.e. the server is NOT vulnerable). The
	// scanner flips this to "ACCEPTED" to flag vulnerability.
	ExpectedReject string
}

// GetPayloads returns all WebAuthn payloads.
func GetPayloads() []Payload {
	return payloads
}

// GetByClass returns payloads filtered by attack class.
func GetByClass(c Class) []Payload {
	var out []Payload
	for _, p := range payloads {
		if p.Class == c {
			out = append(out, p)
		}
	}
	return out
}

// GetByPhase returns payloads filtered by ceremony phase. PhaseBoth
// matches either Registration or Authentication queries.
func GetByPhase(ph Phase) []Payload {
	var out []Payload
	for _, p := range payloads {
		if p.Phase == ph || p.Phase == PhaseBoth {
			out = append(out, p)
		}
	}
	return out
}

// ErrorPatterns returns response substrings that suggest the server is
// running a WebAuthn verification stack — useful as a fingerprint
// preflight before firing flow-level payloads.
func ErrorPatterns() []string {
	return []string{
		"InvalidStateError",
		"NotAllowedError",
		"NotSupportedError",
		"authenticatorData",
		"clientDataJSON",
		"attestationObject",
		"credentialId",
		"publicKeyCredential",
		"PublicKeyCredential",
		"rpId",
		"origin mismatch",
		"invalid challenge",
		"webauthn",
		"FIDO2",
	}
}

// CommonEndpoints returns the curated wordlist of WebAuthn-shaped paths
// the scanner discovery layer uses to surface WebAuthn endpoints.
func CommonEndpoints() []string {
	return []string{
		"/webauthn/register",
		"/webauthn/register/begin",
		"/webauthn/register/finish",
		"/webauthn/login",
		"/webauthn/login/begin",
		"/webauthn/login/finish",
		"/webauthn/authenticate",
		"/api/webauthn/register",
		"/api/webauthn/login",
		"/api/webauthn/authenticate",
		"/api/passkey/register",
		"/api/passkey/login",
		"/api/v1/webauthn/register",
		"/api/v1/webauthn/login",
		"/v1/webauthn",
		"/v2/webauthn",
		"/fido2/attestation/options",
		"/fido2/attestation/result",
		"/fido2/assertion/options",
		"/fido2/assertion/result",
	}
}

var payloads = []Payload{
	// --- Origin pinning (clientDataJSON.origin) ---
	{
		Class:        ClassOriginSpoof,
		Phase:        PhaseBoth,
		Impact:       ImpactAccountTakeover,
		Description:  "clientDataJSON.origin replaced with a same-eTLD+1 host (e.g. attacker.victim.com). RP must compare origin to the registered RP-ID via exact equality after eTLD+1 normalisation.",
		MutationHint: "clientDataJSON.origin = https://attacker.victim.com",
	},
	{
		Class:        ClassOriginSpoof,
		Phase:        PhaseBoth,
		Impact:       ImpactAccountTakeover,
		Description:  "clientDataJSON.origin downgraded to http://. Spec says origin scheme must match the registered scheme; many implementations skip this check.",
		MutationHint: "clientDataJSON.origin = http://victim.com",
	},
	{
		Class:        ClassOriginSpoof,
		Phase:        PhaseBoth,
		Impact:       ImpactAccountTakeover,
		Description:  "clientDataJSON.origin set to a sibling subdomain (login.victim.com → admin.victim.com). RP must pin to the exact origin used at registration.",
		MutationHint: "clientDataJSON.origin = https://admin.victim.com",
	},

	// --- RP-ID substring vs. equality ---
	{
		Class:        ClassRPIDMismatch,
		Phase:        PhaseRegistration,
		Impact:       ImpactRegistration,
		Description:  "Registration RP-ID set to a suffix of the legitimate RP-ID (e.g. RP-ID=evil.com, legit=login.evil.com). Vulnerable implementations accept any suffix match.",
		MutationHint: "publicKey.rp.id = evil.com (when host is login.evil.com)",
	},
	{
		Class:        ClassRPIDMismatch,
		Phase:        PhaseAuthentication,
		Impact:       ImpactAccountTakeover,
		Description:  "Authentication assertion sent to /login.victim.com with rpIdHash for victim.com. Spec requires byte-exact comparison; implementations doing strings.HasSuffix() accept this.",
		MutationHint: "authenticatorData.rpIdHash = sha256(\"victim.com\")",
	},

	// --- Signature counter regression ---
	{
		Class:        ClassCounterRegression,
		Phase:        PhaseAuthentication,
		Impact:       ImpactAuthBypass,
		Description:  "Signature counter sent as 0 or a value LOWER than the previously-observed maximum. Indicates either a clone authenticator or replay. Server MUST refuse or at least raise an alarm.",
		MutationHint: "authenticatorData.signCount = 0 (or prevMax - 1)",
	},
	{
		Class:        ClassCounterRegression,
		Phase:        PhaseAuthentication,
		Impact:       ImpactAuthBypass,
		Description:  "Signature counter set to MaxUint32 to test the wraparound branch — some libraries panic on overflow during the >= comparison.",
		MutationHint: "authenticatorData.signCount = 4294967295",
	},

	// --- Attestation bypass ---
	{
		Class:        ClassAttestationBypass,
		Phase:        PhaseRegistration,
		Impact:       ImpactRegistration,
		Description:  "Registration submitted with attestationStatement format = \"none\" while the registration policy claimed to require packed/tpm/u2f. RP must enforce its declared attestation policy.",
		MutationHint: "attestationObject.fmt = \"none\"",
	},
	{
		Class:        ClassAttestationBypass,
		Phase:        PhaseRegistration,
		Impact:       ImpactRegistration,
		Description:  "Self-attestation submitted against a policy that requires direct (manufacturer-signed) attestation. The Apple AAGUID is a common one.",
		MutationHint: "attestationObject.fmt = \"packed\" with self-attestation cert chain",
	},

	// --- Credential ID reuse across users ---
	{
		Class:        ClassCredentialIDReuse,
		Phase:        PhaseAuthentication,
		Impact:       ImpactAccountTakeover,
		Description:  "Login submitted with userHandle=victim but a credentialID known to belong to a different user. Server must verify (userHandle, credentialID) pair, not just credentialID.",
		MutationHint: "response.userHandle = victim_user_id, credential.id = attacker_credential",
	},

	// --- UV / UP flag downgrade ---
	{
		Class:        ClassUserVerification,
		Phase:        PhaseAuthentication,
		Impact:       ImpactAuthBypass,
		Description:  "UV flag in authenticatorData.flags cleared when policy required \"preferred\" / \"required\". Phishing-resistance gone.",
		MutationHint: "authenticatorData.flags &= ~0x04 (clear UV bit)",
	},
	{
		Class:        ClassUserVerification,
		Phase:        PhaseAuthentication,
		Impact:       ImpactAuthBypass,
		Description:  "UP (user present) flag cleared. Authenticator allegedly produced an assertion with nobody touching the device.",
		MutationHint: "authenticatorData.flags &= ~0x01 (clear UP bit)",
	},

	// --- Challenge reuse / replay ---
	{
		Class:        ClassChallengeReuse,
		Phase:        PhaseBoth,
		Impact:       ImpactAuthBypass,
		Description:  "Submit the same clientDataJSON.challenge that was used in a previous successful ceremony. Replay protection requires server-side one-time challenge tracking.",
		MutationHint: "clientDataJSON.challenge = previously-issued challenge",
	},
	{
		Class:        ClassChallengeReuse,
		Phase:        PhaseBoth,
		Impact:       ImpactAuthBypass,
		Description:  "Submit a clientDataJSON.challenge generated by the attacker but never issued by this server. Server must compare against an in-flight challenge it issued.",
		MutationHint: "clientDataJSON.challenge = attacker-generated random",
	},

	// --- Client-data JSON injection ---
	{
		Class:        ClassClientDataInject,
		Phase:        PhaseBoth,
		Impact:       ImpactAuthBypass,
		Description:  "clientDataJSON contains injected fields (extra keys) that some servers blindly trust. e.g. {\"type\":\"webauthn.get\", \"crossOrigin\":true, \"adminOverride\":true}.",
		MutationHint: "clientDataJSON += attacker-controlled JSON fields",
	},
	{
		Class:        ClassClientDataInject,
		Phase:        PhaseBoth,
		Impact:       ImpactAuthBypass,
		Description:  "clientDataJSON.type mismatched — \"webauthn.create\" sent to a /login endpoint or vice versa. RP must verify the type matches the ceremony.",
		MutationHint: "clientDataJSON.type = wrong-ceremony-string",
	},
}
