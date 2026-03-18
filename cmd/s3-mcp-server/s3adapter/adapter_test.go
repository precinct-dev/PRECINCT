// S3 adapter tests -- unit tests for allowlist enforcement, tool handlers,
// allowlist parsing, and tool schema hash verification.
package s3adapter

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/precinct-dev/precinct/internal/gateway/middleware"
)

// mockS3Client implements S3Client for testing without real AWS calls.
type mockS3Client struct {
	listResult *s3.ListObjectsV2Output
	listErr    error
	getResult  *s3.GetObjectOutput
	getErr     error
}

func (m *mockS3Client) ListObjectsV2(_ context.Context, _ *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	return m.listResult, m.listErr
}

func (m *mockS3Client) GetObject(_ context.Context, _ *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return m.getResult, m.getErr
}

// --- Allowlist enforcement tests ---

func TestIsAllowed_ExactMatch(t *testing.T) {
	a := New(nil, []AllowlistEntry{
		{Bucket: "my-bucket", Prefix: "data/"},
	})

	if !a.IsAllowed("my-bucket", "data/file.txt") {
		t.Error("expected allowed for matching bucket and prefix")
	}
	if !a.IsAllowed("my-bucket", "data/") {
		t.Error("expected allowed for exact prefix match")
	}
}

func TestIsAllowed_Denied_WrongBucket(t *testing.T) {
	a := New(nil, []AllowlistEntry{
		{Bucket: "my-bucket", Prefix: "data/"},
	})

	if a.IsAllowed("other-bucket", "data/file.txt") {
		t.Error("expected denied for wrong bucket")
	}
}

func TestIsAllowed_Denied_WrongPrefix(t *testing.T) {
	a := New(nil, []AllowlistEntry{
		{Bucket: "my-bucket", Prefix: "data/"},
	})

	if a.IsAllowed("my-bucket", "secret/file.txt") {
		t.Error("expected denied for wrong prefix")
	}
}

func TestIsAllowed_Denied_PrefixTraversal(t *testing.T) {
	a := New(nil, []AllowlistEntry{
		{Bucket: "my-bucket", Prefix: "data/public/"},
	})

	if a.IsAllowed("my-bucket", "../secret/file.txt") {
		t.Error("expected denied for path traversal attempt")
	}
	if a.IsAllowed("my-bucket", "data/../secret/file.txt") {
		t.Error("expected denied for embedded traversal (does not start with data/public/)")
	}
}

func TestIsAllowed_MultipleEntries(t *testing.T) {
	a := New(nil, []AllowlistEntry{
		{Bucket: "bucket-a", Prefix: "logs/"},
		{Bucket: "bucket-b", Prefix: "reports/"},
	})

	if !a.IsAllowed("bucket-a", "logs/2024/jan.log") {
		t.Error("expected allowed for bucket-a logs/")
	}
	if !a.IsAllowed("bucket-b", "reports/q1.pdf") {
		t.Error("expected allowed for bucket-b reports/")
	}
	if a.IsAllowed("bucket-a", "reports/q1.pdf") {
		t.Error("expected denied for bucket-a reports/ (wrong prefix)")
	}
}

func TestIsAllowed_EmptyAllowlist(t *testing.T) {
	a := New(nil, nil)

	if a.IsAllowed("any-bucket", "any-key") {
		t.Error("expected denied with empty allowlist")
	}
}

func TestIsAllowed_EmptyPrefix(t *testing.T) {
	a := New(nil, []AllowlistEntry{
		{Bucket: "my-bucket", Prefix: ""},
	})

	if !a.IsAllowed("my-bucket", "anything/goes/here.txt") {
		t.Error("expected allowed with empty prefix (entire bucket)")
	}
}

// --- Allowlist parsing tests ---

func TestParseAllowlist(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []AllowlistEntry
	}{
		{
			name:     "single entry",
			input:    "my-bucket:data/",
			expected: []AllowlistEntry{{Bucket: "my-bucket", Prefix: "data/"}},
		},
		{
			name:  "multiple entries",
			input: "bucket-a:logs/,bucket-b:reports/",
			expected: []AllowlistEntry{
				{Bucket: "bucket-a", Prefix: "logs/"},
				{Bucket: "bucket-b", Prefix: "reports/"},
			},
		},
		{
			name:     "bucket only (no prefix)",
			input:    "my-bucket",
			expected: []AllowlistEntry{{Bucket: "my-bucket", Prefix: ""}},
		},
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:  "whitespace trimming",
			input: " bucket-a:data/ , bucket-b:logs/ ",
			expected: []AllowlistEntry{
				{Bucket: "bucket-a", Prefix: "data/"},
				{Bucket: "bucket-b", Prefix: "logs/"},
			},
		},
		{
			name:     "prefix with colon",
			input:    "my-bucket:path:with:colons/",
			expected: []AllowlistEntry{{Bucket: "my-bucket", Prefix: "path:with:colons/"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ParseAllowlist(tc.input)
			if len(result) != len(tc.expected) {
				t.Fatalf("expected %d entries, got %d", len(tc.expected), len(result))
			}
			for i, r := range result {
				if r.Bucket != tc.expected[i].Bucket || r.Prefix != tc.expected[i].Prefix {
					t.Errorf("entry %d: expected {%q, %q}, got {%q, %q}",
						i, tc.expected[i].Bucket, tc.expected[i].Prefix, r.Bucket, r.Prefix)
				}
			}
		})
	}
}

// --- Tool schema hash verification tests ---

func TestToolSchemaHash_S3ListObjects(t *testing.T) {
	hash := middleware.ComputeHash(ListObjectsDescription, LegacyInputSchema("s3_list_objects"))
	if hash == "" {
		t.Fatal("hash should not be empty")
	}
	if len(hash) != 64 {
		t.Errorf("expected 64-char hex hash, got %d chars: %s", len(hash), hash)
	}
	const expectedHash = "8e007a4ef7ffb625b72e43f04febb0f7409435f9551018b6dbb3d3858fcef0ea"
	if hash != expectedHash {
		t.Errorf("hash mismatch with tool-registry.yaml:\n  computed: %s\n  expected: %s", hash, expectedHash)
	}
	t.Logf("s3_list_objects hash: %s", hash)
}

func TestToolSchemaHash_S3GetObject(t *testing.T) {
	hash := middleware.ComputeHash(GetObjectDescription, LegacyInputSchema("s3_get_object"))
	if hash == "" {
		t.Fatal("hash should not be empty")
	}
	if len(hash) != 64 {
		t.Errorf("expected 64-char hex hash, got %d chars: %s", len(hash), hash)
	}
	const expectedHash = "c2fd4dfceb57d856cdf0bdf9d50d64798dae998d5e107b28220f2fea76c7f7f4"
	if hash != expectedHash {
		t.Errorf("hash mismatch with tool-registry.yaml:\n  computed: %s\n  expected: %s", hash, expectedHash)
	}
	t.Logf("s3_get_object hash: %s", hash)
}

func TestToolSchemaHash_Deterministic(t *testing.T) {
	hash1 := middleware.ComputeHash(ListObjectsDescription, LegacyInputSchema("s3_list_objects"))
	hash2 := middleware.ComputeHash(ListObjectsDescription, LegacyInputSchema("s3_list_objects"))
	if hash1 != hash2 {
		t.Errorf("hash is not deterministic: %s != %s", hash1, hash2)
	}
}

// --- Tool handler tests ---

func TestListObjects_Success(t *testing.T) {
	now := time.Now()
	mock := &mockS3Client{
		listResult: &s3.ListObjectsV2Output{
			Contents: []s3types.Object{
				{Key: aws.String("data/file1.txt"), Size: aws.Int64(100), LastModified: &now},
				{Key: aws.String("data/file2.txt"), Size: aws.Int64(200), LastModified: &now},
			},
		},
	}
	a := New(mock, []AllowlistEntry{
		{Bucket: "test-bucket", Prefix: "data/"},
	})

	result, err := a.ListObjects(context.Background(), map[string]any{
		"bucket": "test-bucket",
		"prefix": "data/",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	text := fmt.Sprintf("%v", result)
	if !strings.Contains(text, "data/file1.txt") {
		t.Error("result should contain file1.txt")
	}
	if !strings.Contains(text, "data/file2.txt") {
		t.Error("result should contain file2.txt")
	}
	if !strings.Contains(text, "count: 2") {
		t.Error("result should contain count: 2")
	}
}

func TestListObjects_Denied(t *testing.T) {
	a := New(nil, []AllowlistEntry{
		{Bucket: "test-bucket", Prefix: "data/"},
	})

	_, err := a.ListObjects(context.Background(), map[string]any{
		"bucket": "test-bucket",
		"prefix": "secret/",
	})
	if err == nil {
		t.Fatal("expected error for access denied")
	}
	if !strings.Contains(err.Error(), "access denied") {
		t.Errorf("expected access denied message, got: %s", err.Error())
	}
}

func TestListObjects_MissingParams(t *testing.T) {
	a := New(nil, []AllowlistEntry{
		{Bucket: "test-bucket", Prefix: "data/"},
	})

	_, err := a.ListObjects(context.Background(), map[string]any{
		"bucket": "",
		"prefix": "data/",
	})
	if err == nil {
		t.Error("expected error for empty bucket")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Error("expected 'required' in error message")
	}
}

func TestListObjects_S3Error(t *testing.T) {
	mock := &mockS3Client{
		listErr: io.ErrUnexpectedEOF,
	}
	a := New(mock, []AllowlistEntry{
		{Bucket: "test-bucket", Prefix: "data/"},
	})

	_, err := a.ListObjects(context.Background(), map[string]any{
		"bucket": "test-bucket",
		"prefix": "data/",
	})
	if err == nil {
		t.Fatal("expected error on S3 failure")
	}
	if !strings.Contains(err.Error(), "ListObjectsV2 failed") {
		t.Error("expected S3 error message")
	}
}

func TestGetObject_Success(t *testing.T) {
	mock := &mockS3Client{
		getResult: &s3.GetObjectOutput{
			Body: io.NopCloser(strings.NewReader("hello world")),
		},
	}
	a := New(mock, []AllowlistEntry{
		{Bucket: "test-bucket", Prefix: "data/"},
	})

	result, err := a.GetObject(context.Background(), map[string]any{
		"bucket": "test-bucket",
		"key":    "data/file.txt",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fmt.Sprintf("%v", result) != "hello world" {
		t.Errorf("expected 'hello world', got %q", result)
	}
}

func TestGetObject_Denied(t *testing.T) {
	a := New(nil, []AllowlistEntry{
		{Bucket: "test-bucket", Prefix: "data/"},
	})

	_, err := a.GetObject(context.Background(), map[string]any{
		"bucket": "test-bucket",
		"key":    "secret/passwords.txt",
	})
	if err == nil {
		t.Fatal("expected error for access denied")
	}
	if !strings.Contains(err.Error(), "access denied") {
		t.Error("expected access denied message")
	}
}

func TestGetObject_MissingParams(t *testing.T) {
	a := New(nil, []AllowlistEntry{
		{Bucket: "test-bucket", Prefix: "data/"},
	})

	_, err := a.GetObject(context.Background(), map[string]any{
		"bucket": "test-bucket",
		"key":    "",
	})
	if err == nil {
		t.Error("expected error for empty key")
	}
}

func TestGetObject_S3Error(t *testing.T) {
	mock := &mockS3Client{
		getErr: io.ErrUnexpectedEOF,
	}
	a := New(mock, []AllowlistEntry{
		{Bucket: "test-bucket", Prefix: "data/"},
	})

	_, err := a.GetObject(context.Background(), map[string]any{
		"bucket": "test-bucket",
		"key":    "data/file.txt",
	})
	if err == nil {
		t.Fatal("expected error on S3 failure")
	}
	if !strings.Contains(err.Error(), "GetObject failed") {
		t.Error("expected S3 error message")
	}
}
