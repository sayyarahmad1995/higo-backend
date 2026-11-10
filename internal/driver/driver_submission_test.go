package driver

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"testing"
)

func TestDriverImageLimits(t *testing.T) {
	// A PNG header can declare enormous dimensions before any pixels are read.
	header := []byte{137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 'I', 'H', 'D', 'R', 0, 0, 0, 0, 0, 0, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(header[16:], 4096)
	binary.BigEndian.PutUint32(header[20:], 4096)
	binary.BigEndian.PutUint32(header[29:], crc32.ChecksumIEEE(header[12:29]))
	for _, scenario := range []struct {
		name string
		data []byte
		want error
	}{
		{"oversized", make([]byte, maxDriverImage+1), documentTooLarge},
		{"deceptive JPEG signature", []byte{0xff, 0xd8, 0xff, 1, 2, 3}, invalidDocument},
		{"unsupported GIF", []byte("GIF89a"), invalidDocument},
		{"excessive pixels", header, invalidDocument},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if _, err := normalizeDriverImage(scenario.data); err != scenario.want {
				t.Fatalf("error = %v, want %v", err, scenario.want)
			}
		})
	}
	output := boundedDriverImage{limit: maxDriverImage}
	if _, err := output.Write(bytes.Repeat([]byte{1}, maxDriverImage)); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte{1}); err != documentTooLarge || output.Len() != maxDriverImage {
		t.Fatal("normalized output exceeded its budget")
	}
}
