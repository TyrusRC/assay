// Package cloud provides payloads for cloud misconfiguration detection.
package cloud

// Provider represents a cloud provider.
type Provider string

const (
	ProviderAWS   Provider = "aws"
	ProviderGCP   Provider = "gcp"
	ProviderAzure Provider = "azure"
)

// ResourceType represents the type of cloud resource.
type ResourceType string

const (
	ResourceBucket   ResourceType = "bucket"
	ResourceBlob     ResourceType = "blob"
	ResourceFunction ResourceType = "function"
	ResourceAPI      ResourceType = "api"
)

// BucketCheck represents a cloud storage misconfiguration check.
type BucketCheck struct {
	URLTemplate string
	Provider    Provider
	Resource    ResourceType
	Description string
	Patterns    []string // Patterns indicating misconfiguration
}

var bucketChecks = []BucketCheck{
	// AWS S3
	{URLTemplate: "https://{BUCKET}.s3.amazonaws.com", Provider: ProviderAWS, Resource: ResourceBucket, Description: "S3 bucket listing", Patterns: []string{"<ListBucketResult", "<Contents>", "<Key>"}},
	{URLTemplate: "https://s3.amazonaws.com/{BUCKET}", Provider: ProviderAWS, Resource: ResourceBucket, Description: "S3 path-style listing", Patterns: []string{"<ListBucketResult", "<Contents>"}},
	{URLTemplate: "https://{BUCKET}.s3.amazonaws.com/?acl", Provider: ProviderAWS, Resource: ResourceBucket, Description: "S3 bucket ACL", Patterns: []string{"<AccessControlPolicy", "<Grant>", "<Permission>"}},
	{URLTemplate: "https://{BUCKET}.s3.amazonaws.com/?policy", Provider: ProviderAWS, Resource: ResourceBucket, Description: "S3 bucket policy", Patterns: []string{`"Statement"`, `"Effect"`, `"Principal"`}},

	// GCP Cloud Storage
	{URLTemplate: "https://storage.googleapis.com/{BUCKET}", Provider: ProviderGCP, Resource: ResourceBucket, Description: "GCS bucket listing", Patterns: []string{"<ListBucketResult", "<Contents>", "storage.googleapis.com"}},
	{URLTemplate: "https://storage.googleapis.com/{BUCKET}?acl", Provider: ProviderGCP, Resource: ResourceBucket, Description: "GCS bucket ACL", Patterns: []string{"<AccessControlList", "<Entries>"}},
	{URLTemplate: "https://{BUCKET}.storage.googleapis.com", Provider: ProviderGCP, Resource: ResourceBucket, Description: "GCS subdomain listing", Patterns: []string{"<ListBucketResult", "<Contents>"}},

	// Azure Blob Storage
	{URLTemplate: "https://{ACCOUNT}.blob.core.windows.net/{CONTAINER}?restype=container&comp=list", Provider: ProviderAzure, Resource: ResourceBlob, Description: "Azure blob listing", Patterns: []string{"<EnumerationResults", "<Blobs>", "<Blob>"}},
	{URLTemplate: "https://{ACCOUNT}.blob.core.windows.net/{CONTAINER}?restype=container&comp=acl", Provider: ProviderAzure, Resource: ResourceBlob, Description: "Azure blob ACL", Patterns: []string{"<SignedIdentifiers"}},
}

// CommonBucketNames are common bucket name patterns to check.
var CommonBucketNames = []string{
	"{DOMAIN}",
	"{DOMAIN}-backup",
	"{DOMAIN}-backups",
	"{DOMAIN}-data",
	"{DOMAIN}-dev",
	"{DOMAIN}-staging",
	"{DOMAIN}-prod",
	"{DOMAIN}-production",
	"{DOMAIN}-assets",
	"{DOMAIN}-static",
	"{DOMAIN}-media",
	"{DOMAIN}-uploads",
	"{DOMAIN}-logs",
	"{DOMAIN}-config",
	"{DOMAIN}-private",
	"{DOMAIN}-public",
	"{DOMAIN}-internal",
	"{DOMAIN}-archive",
	"www-{DOMAIN}",
	"api-{DOMAIN}",
}

// GetBucketChecks returns all cloud bucket misconfiguration checks.
func GetBucketChecks() []BucketCheck {
	return bucketChecks
}

// GetByProvider returns checks for a specific cloud provider.
func GetByProvider(provider Provider) []BucketCheck {
	var result []BucketCheck
	for _, c := range bucketChecks {
		if c.Provider == provider {
			result = append(result, c)
		}
	}
	return result
}

// GetCommonBucketNames returns common bucket name patterns.
func GetCommonBucketNames() []string {
	return CommonBucketNames
}
