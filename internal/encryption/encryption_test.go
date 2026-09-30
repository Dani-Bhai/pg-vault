package encryption

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"testing"
)

func newKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func TestRoundTrip(t *testing.T) {
	key := newKey(t)
	noncePrefix, err := NewNoncePrefix()
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte(`{"backup_id":"test"}`)

	sizes := []int{0, 1, 63, 64, 65, 127, 128, 1000, 4096}
	for _, size := range sizes {
		plaintext := make([]byte, size)
		if _, err := rand.Read(plaintext); err != nil {
			t.Fatal(err)
		}

		var buf bytes.Buffer
		writer, err := NewWriter(&buf, key, noncePrefix, aad, 64)
		if err != nil {
			t.Fatalf("size %d: new writer: %v", size, err)
		}
		if _, err := writer.Write(plaintext); err != nil {
			t.Fatalf("size %d: write: %v", size, err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("size %d: close: %v", size, err)
		}

		reader, err := NewReader(&buf, key, noncePrefix, aad, 64)
		if err != nil {
			t.Fatalf("size %d: new reader: %v", size, err)
		}
		got, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("size %d: read: %v", size, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("size %d: round trip mismatch", size)
		}
	}
}

func TestFragmentedWrites(t *testing.T) {
	key := newKey(t)
	noncePrefix, _ := NewNoncePrefix()
	aad := []byte("aad")

	plaintext := make([]byte, 1000)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	writer, err := NewWriter(&buf, key, noncePrefix, aad, 64)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(plaintext); i += 7 {
		end := min(i+7, len(plaintext))
		if _, err := writer.Write(plaintext[i:end]); err != nil {
			t.Fatalf("write at %d: %v", i, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	reader, err := NewReader(&buf, key, noncePrefix, aad, 64)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("fragmented round trip mismatch")
	}
}

func TestWrongKeyFails(t *testing.T) {
	key := newKey(t)
	noncePrefix, _ := NewNoncePrefix()
	aad := []byte("aad")
	plaintext := bytes.Repeat([]byte("x"), 200)

	var buf bytes.Buffer
	writer, _ := NewWriter(&buf, key, noncePrefix, aad, 64)
	writer.Write(plaintext)
	writer.Close()

	reader, err := NewReader(&buf, newKey(t), noncePrefix, aad, 64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); err == nil {
		t.Fatal("expected decryption with a wrong key to fail")
	}
}

func TestTamperedCiphertextFails(t *testing.T) {
	key := newKey(t)
	noncePrefix, _ := NewNoncePrefix()
	aad := []byte("aad")

	var buf bytes.Buffer
	writer, _ := NewWriter(&buf, key, noncePrefix, aad, 64)
	writer.Write(bytes.Repeat([]byte("x"), 200))
	writer.Close()

	raw := buf.Bytes()
	raw[len(raw)-3] ^= 0xff

	reader, err := NewReader(bytes.NewReader(raw), key, noncePrefix, aad, 64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); err == nil {
		t.Fatal("expected tampered ciphertext to fail")
	}
}

func TestTamperedAADFails(t *testing.T) {
	key := newKey(t)
	noncePrefix, _ := NewNoncePrefix()

	var buf bytes.Buffer
	writer, _ := NewWriter(&buf, key, noncePrefix, []byte("original header"), 64)
	writer.Write(bytes.Repeat([]byte("x"), 200))
	writer.Close()

	reader, err := NewReader(&buf, key, noncePrefix, []byte("modified header"), 64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); err == nil {
		t.Fatal("expected modified AAD to fail authentication")
	}
}

func TestTruncatedStreamFails(t *testing.T) {
	key := newKey(t)
	noncePrefix, _ := NewNoncePrefix()
	aad := []byte("aad")

	var buf bytes.Buffer
	writer, _ := NewWriter(&buf, key, noncePrefix, aad, 64)
	writer.Write(bytes.Repeat([]byte("x"), 200))
	writer.Close()

	raw := buf.Bytes()[:len(buf.Bytes())-5]

	reader, err := NewReader(bytes.NewReader(raw), key, noncePrefix, aad, 64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); err == nil {
		t.Fatal("expected truncated stream to fail")
	}
}

func TestParseMasterKey(t *testing.T) {
	key := newKey(t)

	hexRaw := fmt.Sprintf("%x", key)
	parsed, err := ParseMasterKey(hexRaw)
	if err != nil || !bytes.Equal(parsed, key) {
		t.Fatalf("hex key: %v", err)
	}

	b64Raw := base64.StdEncoding.EncodeToString(key)
	parsed, err = ParseMasterKey(b64Raw)
	if err != nil || !bytes.Equal(parsed, key) {
		t.Fatalf("base64 key: %v", err)
	}

	if _, err := ParseMasterKey("too-short"); err == nil {
		t.Fatal("expected invalid key to be rejected")
	}
}
