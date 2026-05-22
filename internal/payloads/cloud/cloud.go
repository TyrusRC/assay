// Package cloud provides payloads for cloud misconfiguration detection.
package cloud

// Provider represents a cloud provider.
type Provider string

const (
	ProviderAWS          Provider = "aws"
	ProviderGCP          Provider = "gcp"
	ProviderAzure        Provider = "azure"
	ProviderAlibaba      Provider = "alibaba"
	ProviderDigitalOcean Provider = "digitalocean"
	ProviderWasabi       Provider = "wasabi"
	ProviderBackblaze    Provider = "backblaze"
	ProviderLinode       Provider = "linode"
	ProviderTencent      Provider = "tencent"
	ProviderIBM          Provider = "ibm"
	ProviderOracle       Provider = "oracle"
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

	// --- HackTricks Cloud expansion ---

	// Azure storage: additional endpoints. File / Queue / Table
	// storage have separate hostnames; static-website hosting hangs
	// off blob.core.windows.net/$web.
	{URLTemplate: "https://{ACCOUNT}.file.core.windows.net/{SHARE}?restype=share&comp=list", Provider: ProviderAzure, Resource: ResourceBlob, Description: "Azure file share listing", Patterns: []string{"<EnumerationResults"}},
	{URLTemplate: "https://{ACCOUNT}.queue.core.windows.net/?comp=list", Provider: ProviderAzure, Resource: ResourceBlob, Description: "Azure queue enumeration", Patterns: []string{"<EnumerationResults"}},
	{URLTemplate: "https://{ACCOUNT}.blob.core.windows.net/$web?restype=container&comp=list", Provider: ProviderAzure, Resource: ResourceBlob, Description: "Azure static website ($web)", Patterns: []string{"<EnumerationResults"}},
	{URLTemplate: "https://{ACCOUNT}.dfs.core.windows.net/{CONTAINER}?resource=filesystem", Provider: ProviderAzure, Resource: ResourceBlob, Description: "Azure Data Lake Gen2 (dfs)", Patterns: []string{"\"name\"", "\"paths\""}},

	// AWS additional surfaces. CloudFront origin-bucket leak via
	// X-Amz-Bucket-Region header check (path-style + region probe);
	// AWS Object Lambda; AWS Lake Formation buckets follow a region
	// subdomain pattern.
	{URLTemplate: "https://{BUCKET}.s3.{REGION}.amazonaws.com", Provider: ProviderAWS, Resource: ResourceBucket, Description: "S3 region-subdomain listing", Patterns: []string{"<ListBucketResult"}},
	{URLTemplate: "https://{BUCKET}.s3-accelerate.amazonaws.com", Provider: ProviderAWS, Resource: ResourceBucket, Description: "S3 Transfer Acceleration endpoint", Patterns: []string{"<ListBucketResult"}},
	{URLTemplate: "https://{BUCKET}.s3.dualstack.{REGION}.amazonaws.com", Provider: ProviderAWS, Resource: ResourceBucket, Description: "S3 dual-stack (IPv6) endpoint", Patterns: []string{"<ListBucketResult"}},
	{URLTemplate: "https://{BUCKET}.s3-website.{REGION}.amazonaws.com", Provider: ProviderAWS, Resource: ResourceBucket, Description: "S3 static-website endpoint", Patterns: []string{"<title>", "<html"}},

	// GCP additional surfaces — XML and JSON API
	{URLTemplate: "https://www.googleapis.com/storage/v1/b/{BUCKET}/o", Provider: ProviderGCP, Resource: ResourceBucket, Description: "GCS JSON API list", Patterns: []string{"\"items\"", "\"selfLink\""}},
	{URLTemplate: "https://www.googleapis.com/storage/v1/b/{BUCKET}/iam", Provider: ProviderGCP, Resource: ResourceBucket, Description: "GCS bucket IAM policy", Patterns: []string{"\"bindings\"", "\"role\""}},

	// Alibaba Cloud OSS — region subdomain pattern.
	{URLTemplate: "https://{BUCKET}.oss-{REGION}.aliyuncs.com/?list-type=2", Provider: ProviderAlibaba, Resource: ResourceBucket, Description: "Alibaba OSS listing", Patterns: []string{"<ListBucketResult", "<Contents>"}},
	{URLTemplate: "https://{BUCKET}.oss-cn-hangzhou.aliyuncs.com/?acl", Provider: ProviderAlibaba, Resource: ResourceBucket, Description: "Alibaba OSS ACL (default region)", Patterns: []string{"<AccessControlPolicy"}},

	// DigitalOcean Spaces (S3-compatible)
	{URLTemplate: "https://{BUCKET}.nyc3.digitaloceanspaces.com", Provider: ProviderDigitalOcean, Resource: ResourceBucket, Description: "DO Spaces nyc3", Patterns: []string{"<ListBucketResult"}},
	{URLTemplate: "https://{BUCKET}.sfo3.digitaloceanspaces.com", Provider: ProviderDigitalOcean, Resource: ResourceBucket, Description: "DO Spaces sfo3", Patterns: []string{"<ListBucketResult"}},
	{URLTemplate: "https://{BUCKET}.ams3.digitaloceanspaces.com", Provider: ProviderDigitalOcean, Resource: ResourceBucket, Description: "DO Spaces ams3", Patterns: []string{"<ListBucketResult"}},

	// Wasabi (S3-compatible)
	{URLTemplate: "https://s3.wasabisys.com/{BUCKET}", Provider: ProviderWasabi, Resource: ResourceBucket, Description: "Wasabi path-style", Patterns: []string{"<ListBucketResult"}},
	{URLTemplate: "https://{BUCKET}.s3.wasabisys.com", Provider: ProviderWasabi, Resource: ResourceBucket, Description: "Wasabi virtual-host", Patterns: []string{"<ListBucketResult"}},

	// Backblaze B2
	{URLTemplate: "https://f000.backblazeb2.com/file/{BUCKET}/", Provider: ProviderBackblaze, Resource: ResourceBucket, Description: "Backblaze B2 file API", Patterns: []string{"\"files\"", "\"fileName\""}},

	// Linode Object Storage (S3-compatible)
	{URLTemplate: "https://{BUCKET}.us-east-1.linodeobjects.com", Provider: ProviderLinode, Resource: ResourceBucket, Description: "Linode Object Storage", Patterns: []string{"<ListBucketResult"}},

	// Tencent Cloud COS
	{URLTemplate: "https://{BUCKET}.cos.ap-guangzhou.myqcloud.com", Provider: ProviderTencent, Resource: ResourceBucket, Description: "Tencent COS (ap-guangzhou)", Patterns: []string{"<ListBucketResult"}},
	{URLTemplate: "https://{BUCKET}.cos.ap-beijing.myqcloud.com", Provider: ProviderTencent, Resource: ResourceBucket, Description: "Tencent COS (ap-beijing)", Patterns: []string{"<ListBucketResult"}},

	// IBM Cloud Object Storage
	{URLTemplate: "https://s3.us-south.cloud-object-storage.appdomain.cloud/{BUCKET}", Provider: ProviderIBM, Resource: ResourceBucket, Description: "IBM COS us-south", Patterns: []string{"<ListBucketResult"}},

	// Oracle Cloud Object Storage
	{URLTemplate: "https://objectstorage.us-ashburn-1.oraclecloud.com/n/{NAMESPACE}/b/{BUCKET}/o", Provider: ProviderOracle, Resource: ResourceBucket, Description: "Oracle OCI Object Storage", Patterns: []string{"\"objects\""}},
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

	// HackTricks Cloud-inspired permutations the existing list missed
	"{DOMAIN}-build",
	"{DOMAIN}-builds",
	"{DOMAIN}-ci",
	"{DOMAIN}-artifacts",
	"{DOMAIN}-releases",
	"{DOMAIN}-secrets",
	"{DOMAIN}-terraform",
	"{DOMAIN}-tf-state",
	"{DOMAIN}-cf-templates",
	"{DOMAIN}-cloudtrail",
	"{DOMAIN}-elb-logs",
	"{DOMAIN}-vpc-flow-logs",
	"{DOMAIN}-cloudfront-logs",
	"{DOMAIN}-static-prod",
	"{DOMAIN}-static-dev",
	"{DOMAIN}-uploads-prod",
	"{DOMAIN}-uploads-dev",
	"{DOMAIN}-test",
	"{DOMAIN}-qa",
	"{DOMAIN}-temp",
	"{DOMAIN}-tmp",
	"{DOMAIN}-old",
	"{DOMAIN}-deprecated",
	"backup-{DOMAIN}",
	"data-{DOMAIN}",
	"assets-{DOMAIN}",
	"static-{DOMAIN}",
	"media-{DOMAIN}",
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
