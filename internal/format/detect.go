package format

import (
	"encoding/binary"
	"errors"
)

// Kind describes a recognized executable container.
type Kind string

const (
	KindUnknown Kind = "unknown"
	KindPE      Kind = "pe"
	KindELF     Kind = "elf"
	KindMachO   Kind = "macho"
)

var (
	ErrTooSmall = errors.New("file too small for format detection")
)

// Detect inspects the header of data and returns the container kind.
func Detect(data []byte) (Kind, error) {
	if len(data) < 4 {
		return KindUnknown, ErrTooSmall
	}
	if len(data) >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
		return KindELF, nil
	}
	if len(data) >= 4 {
		switch binary.BigEndian.Uint32(data[0:4]) {
		case 0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE:
			return KindMachO, nil
		}
	}
	if len(data) >= 64 && data[0] == 'M' && data[1] == 'Z' {
		peOff := int(binary.LittleEndian.Uint32(data[0x3c : 0x40]))
		if peOff < 0 || peOff+4 > len(data) {
			return KindUnknown, nil
		}
		if data[peOff] == 'P' && data[peOff+1] == 'E' && data[peOff+2] == 0 && data[peOff+3] == 0 {
			return KindPE, nil
		}
	}
	return KindUnknown, nil
}

// DetectFile reads up to limit bytes from path for detection.
func DetectFromBytes(data []byte) Kind {
	k, _ := Detect(data)
	return k
}
