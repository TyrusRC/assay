// Package iast provides a lightweight Interactive Application Security
// Testing (IAST) layer for assay.
//
// The IAST module works alongside assay's DAST detectors to confirm that
// injection payloads actually reach dangerous sinks inside the target
// application. It has two parts:
//
//  1. Callback server (this package) — an HTTP server inside assay that
//     receives POST reports from deployed sensors when a taint marker
//     reaches a sink. Runs on :7880 by default.
//
//  2. Sensors (sensors/ subdirectory) — small PHP, Node.js and Python
//     files deployed to the target app. Each sensor hooks language-level
//     dangerous functions (SQL query, system command, file open, URL
//     open, unserialize, etc.) and checks whether the input contains an
//     assay taint marker. When a marker is found the sensor POSTs the
//     sink type, value, and stack trace to the callback server.
//
// Flow:
//
//	DAST detector injects payload with taint marker →
//	  target app processes payload →
//	    sensor detects marker at sink →
//	      sensor POSTs SinkHit to callback server →
//	        assay upgrades finding confidence to "confirmed"
//
// The taint marker is a deterministic string wrapper around the original
// payload: ASSAY_TAINT_<id>_<sink>_<payload>_TAINT_ASSAY. The id is an
// 8-character hex string generated per probe. Sensors match on the
// prefix/suffix pair and extract the id to correlate with the original
// DAST finding.
package iast
