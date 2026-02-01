// Package subtakeover provides fingerprints for subdomain takeover detection.
package subtakeover

// Service represents a cloud service that can be taken over.
type Service struct {
	Name        string
	CNames      []string // CNAME patterns indicating the service
	Fingerprint []string // HTTP response fingerprints indicating takeover
	NXDomain    bool     // Service is vulnerable if CNAME points to NXDOMAIN
	HTTPCheck   bool     // Requires HTTP response check
	Severity    string   // critical, high, medium
}

var services = []Service{
	{
		Name:        "GitHub Pages",
		CNames:      []string{".github.io"},
		Fingerprint: []string{"There isn't a GitHub Pages site here.", "For root URLs (like http://example.com/) you must provide an index.html file"},
		HTTPCheck:   true,
		Severity:    "high",
	},
	{
		Name:        "Heroku",
		CNames:      []string{".herokuapp.com", ".herokussl.com"},
		Fingerprint: []string{"No such app", "no-such-app", "herokucdn.com/error-pages/no-such-app"},
		HTTPCheck:   true,
		Severity:    "high",
	},
	{
		Name:        "AWS S3",
		CNames:      []string{".s3.amazonaws.com", ".s3-website", ".s3.us-", ".s3.eu-", ".s3.ap-"},
		Fingerprint: []string{"NoSuchBucket", "The specified bucket does not exist"},
		HTTPCheck:   true,
		Severity:    "high",
	},
	{
		Name:        "AWS Elastic Beanstalk",
		CNames:      []string{".elasticbeanstalk.com"},
		Fingerprint: []string{},
		NXDomain:    true,
		Severity:    "high",
	},
	{
		Name:        "AWS CloudFront",
		CNames:      []string{".cloudfront.net"},
		Fingerprint: []string{"ERROR: The request could not be satisfied", "Bad request", "The distribution is not configured"},
		HTTPCheck:   true,
		Severity:    "high",
	},
	{
		Name:        "Azure",
		CNames:      []string{".azurewebsites.net", ".cloudapp.net", ".cloudapp.azure.com", ".trafficmanager.net", ".blob.core.windows.net", ".azure-api.net", ".azurefd.net"},
		Fingerprint: []string{"404 Web Site not found", "Web App - Pair With Microsoft Azure"},
		HTTPCheck:   true,
		Severity:    "high",
	},
	{
		Name:        "Shopify",
		CNames:      []string{".myshopify.com"},
		Fingerprint: []string{"Sorry, this shop is currently unavailable", "Only one step left"},
		HTTPCheck:   true,
		Severity:    "high",
	},
	{
		Name:        "Fastly",
		CNames:      []string{".fastly.net", ".fastlylb.net"},
		Fingerprint: []string{"Fastly error: unknown domain"},
		HTTPCheck:   true,
		Severity:    "high",
	},
	{
		Name:        "Pantheon",
		CNames:      []string{".pantheonsite.io"},
		Fingerprint: []string{"404 error unknown site", "The gods are wise"},
		HTTPCheck:   true,
		Severity:    "high",
	},
	{
		Name:        "Tumblr",
		CNames:      []string{".tumblr.com"},
		Fingerprint: []string{"Whatever you were looking for doesn't currently exist at this address", "There's nothing here"},
		HTTPCheck:   true,
		Severity:    "medium",
	},
	{
		Name:        "WordPress.com",
		CNames:      []string{".wordpress.com"},
		Fingerprint: []string{"Do you want to register"},
		HTTPCheck:   true,
		Severity:    "medium",
	},
	{
		Name:        "Zendesk",
		CNames:      []string{".zendesk.com"},
		Fingerprint: []string{"Help Center Closed", "this help center no longer exists"},
		HTTPCheck:   true,
		Severity:    "medium",
	},
	{
		Name:        "Surge.sh",
		CNames:      []string{".surge.sh"},
		Fingerprint: []string{"project not found"},
		HTTPCheck:   true,
		NXDomain:    true,
		Severity:    "high",
	},
	{
		Name:        "Netlify",
		CNames:      []string{".netlify.app", ".netlify.com"},
		Fingerprint: []string{"Not Found - Request ID"},
		HTTPCheck:   true,
		Severity:    "high",
	},
	{
		Name:        "Fly.io",
		CNames:      []string{".fly.dev"},
		Fingerprint: []string{},
		NXDomain:    true,
		Severity:    "high",
	},
	{
		Name:        "Cargo Collective",
		CNames:      []string{".cargocollective.com"},
		Fingerprint: []string{"404 Not Found"},
		HTTPCheck:   true,
		Severity:    "medium",
	},
	{
		Name:        "Unbounce",
		CNames:      []string{".unbouncepages.com"},
		Fingerprint: []string{"The requested URL was not found on this server", "The page you're looking for can't be found"},
		HTTPCheck:   true,
		Severity:    "medium",
	},
}

// GetServices returns all subdomain takeover service fingerprints.
func GetServices() []Service {
	return services
}

// GetServiceByCNAME returns the service matching a CNAME record.
func GetServiceByCNAME(cname string) *Service {
	for _, svc := range services {
		for _, pattern := range svc.CNames {
			if len(cname) > len(pattern) && cname[len(cname)-len(pattern):] == pattern {
				return &svc
			}
		}
	}
	return nil
}
