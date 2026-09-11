package gocloak

import (
	"bytes"
	"testing"
)

// FuzzHelloFrame fuzzes both frame parsers against arbitrary bytes. Neither
// parser should ever panic, and readHelloRequest must never return a name
// that fails its own charset check, regardless of what bytes it was fed:
// the codec is the boundary that receives input from an authenticated but
// possibly compromised peer, so it must survive anything.
func FuzzHelloFrame(f *testing.F) {
	seeds := [][]byte{
		{},
		{0x01},
		{0x01, 0x00},
		{0x01, 0x01, 'a'},
		{0x01, 0x03, 'a', 'b', 'c'},
		{0x01, 0x3f},
		append([]byte{0x01, 0x3f}, bytes.Repeat([]byte{'a'}, 63)...),
		{0x01, 0x40},
		append([]byte{0x01, 0x40}, bytes.Repeat([]byte{'a'}, 64)...),
		{0x01, 0xff},
		{0x02, 0x01, 'a'},
		{0x01, 0x01, 'A'},
		{0x01, 0x02, 'a', 0x00},
		{0x01, 0x02, '-', 'a'},
		{0x00, 0x00},
		{0x01, 0x00},
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		name, err := readHelloRequest(bytes.NewReader(data))
		if err == nil {
			if !ValidServiceName(name) {
				t.Fatalf("readHelloRequest accepted a name that fails its own charset check: %q", name)
			}
			if len(name) == 0 || len(name) > maxNameLen {
				t.Fatalf("readHelloRequest accepted an out-of-range name length: %d", len(name))
			}
		}

		status, err := readHelloResponse(bytes.NewReader(data))
		if err == nil && !validStatus(status) {
			t.Fatalf("readHelloResponse accepted an unknown status byte: %v", status)
		}
	})
}
