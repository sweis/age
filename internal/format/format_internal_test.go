// Copyright 2021 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package format

import (
	"bytes"
	"testing"
)

func TestWriteWrappedReturnsCorrectLength(t *testing.T) {
	var dst bytes.Buffer
	w := &WrappedBase64Encoder{dst: &dst}

	// Use more than ColumnsPerLine bytes so the loop slices p multiple times.
	input := bytes.Repeat([]byte("A"), 100)
	n, err := w.writeWrapped(input)
	if err != nil {
		t.Fatalf("writeWrapped returned unexpected error: %v", err)
	}
	if n != len(input) {
		t.Errorf("writeWrapped returned n = %d, want %d", n, len(input))
	}
	// The output must include at least len(input) bytes (plus inserted newlines).
	if dst.Len() < len(input) {
		t.Errorf("destination received %d bytes, expected at least %d", dst.Len(), len(input))
	}
}
