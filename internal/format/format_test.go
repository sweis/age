// Copyright 2021 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18

package format_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age/internal/format"
)

func TestStanzaMarshal(t *testing.T) {
	s := &format.Stanza{
		Type: "test",
		Args: []string{"1", "2", "3"},
		Body: nil, // empty
	}
	buf := &bytes.Buffer{}
	s.Marshal(buf)
	if exp := "-> test 1 2 3\n\n"; buf.String() != exp {
		t.Errorf("wrong empty stanza encoding: expected %q, got %q", exp, buf.String())
	}

	buf.Reset()
	s.Body = []byte("AAA")
	s.Marshal(buf)
	if exp := "-> test 1 2 3\nQUFB\n"; buf.String() != exp {
		t.Errorf("wrong normal stanza encoding: expected %q, got %q", exp, buf.String())
	}

	buf.Reset()
	s.Body = bytes.Repeat([]byte("A"), format.BytesPerLine)
	s.Marshal(buf)
	if exp := "-> test 1 2 3\nQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\n\n"; buf.String() != exp {
		t.Errorf("wrong 64 columns stanza encoding: expected %q, got %q", exp, buf.String())
	}
}

// stanzaBodyReader emits an unbounded sequence of valid 64-column stanza
// body lines, so Parse sees a syntactically valid but never-ending stanza.
type stanzaBodyReader struct {
	line []byte
	off  int
}

func (r *stanzaBodyReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		c := copy(p[n:], r.line[r.off:])
		n += c
		r.off = (r.off + c) % len(r.line)
	}
	return n, nil
}

func TestParseHeaderSizeLimit(t *testing.T) {
	// A body line of exactly ColumnsPerLine base64 chars keeps the stanza
	// open, so the reader below never yields a short line and Parse would
	// read forever without the header size cap.
	line := strings.Repeat("A", format.ColumnsPerLine) + "\n"
	r := io.MultiReader(
		strings.NewReader("age-encryption.org/v1\n-> X\n"),
		&stanzaBodyReader{line: []byte(line)},
	)

	_, _, err := format.Parse(r)
	if err == nil {
		t.Fatal("Parse of >16 MiB header succeeded; want error")
	}
	if !strings.Contains(err.Error(), "header exceeds") {
		t.Fatalf("Parse error = %q; want error mentioning %q", err, "header exceeds")
	}
}

func FuzzMalleability(f *testing.F) {
	tests, err := filepath.Glob("../../testdata/testkit/*")
	if err != nil {
		f.Fatal(err)
	}
	for _, test := range tests {
		contents, err := os.ReadFile(test)
		if err != nil {
			f.Fatal(err)
		}
		_, contents, ok := bytes.Cut(contents, []byte("\n\n"))
		if !ok {
			f.Fatal("testkit file without header")
		}
		f.Add(contents)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		h, payload, err := format.Parse(bytes.NewReader(data))
		if err != nil {
			if h != nil {
				t.Error("h != nil on error")
			}
			if payload != nil {
				t.Error("payload != nil on error")
			}
			t.Skip()
		}
		w := &bytes.Buffer{}
		if err := h.Marshal(w); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(w, payload); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(w.Bytes(), data) {
			t.Error("Marshal output different from input")
		}
	})
}
