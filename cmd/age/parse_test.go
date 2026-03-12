// Copyright 2024 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"testing"
)

// TestSSHKeyTypeOverflowLength is a regression test for a bug where a
// malformed SSH public key blob with a type-length prefix larger than the
// remaining buffer could cause a panic on 32-bit platforms. On such
// platforms, casting a uint32 value above 2^31-1 to int yields a negative
// number, which triggers a runtime panic inside cryptobyte.ReadBytes.
//
// The fix bounds-checks the length against the remaining buffer before the
// cast, so this input is now rejected gracefully on all platforms.
func TestSSHKeyTypeOverflowLength(t *testing.T) {
	tests := []struct {
		name   string
		length [4]byte
	}{
		{
			// 0xFFFFFFFF: wraps to -1 as a signed 32-bit int.
			name:   "max uint32",
			length: [4]byte{0xFF, 0xFF, 0xFF, 0xFF},
		},
		{
			// 0x80000000: wraps to the most negative 32-bit int.
			name:   "min negative int32",
			length: [4]byte{0x80, 0x00, 0x00, 0x00},
		},
		{
			// Positive as an int32 but still far larger than the buffer.
			name:   "large positive",
			length: [4]byte{0x7F, 0xFF, 0xFF, 0xFF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("sshKeyType panicked: %v", r)
				}
			}()

			// Build a blob with the crafted 4-byte length prefix followed
			// by a few trailing bytes (far fewer than the prefix claims).
			blob := append(tt.length[:], []byte("junk")...)
			line := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob)

			typ, ok := sshKeyType(line)
			if ok {
				t.Fatalf("sshKeyType(%q) = %q, true; want \"\", false", line, typ)
			}
			if typ != "" {
				t.Fatalf("sshKeyType(%q) returned type %q; want empty string", line, typ)
			}
		})
	}
}
