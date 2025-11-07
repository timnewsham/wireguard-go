package netstack

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"
)

type PcapFile struct {
	fp *os.File
}

func NewPcapFile(fn string) (*PcapFile, error) {
	fp, err := os.Create(fn)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fn, err)
	}
	p := &PcapFile{fp}
	if err := p.WriteHeader(); err != nil {
		defer p.Close()
		return nil, fmt.Errorf("%s: writing header: %w", fn, err)
	}
	return p, nil
}

type fhdr struct {
	magic    uint32
	majv     uint16
	minv     uint16
	res1     uint32
	res2     uint32
	snaplen  uint32
	fcs      uint16
	linktype uint16
}

func (p *PcapFile) WriteHeader() error {
	h := fhdr{
		magic:    0xa1b23c4d,
		majv:     2,
		minv:     4,
		linktype: 0, // 0 = null? for tun
	}
	return binary.Write(p.fp, binary.LittleEndian, &h)
}

type phdr struct {
	sec    uint32
	nsec   uint32
	caplen uint32
	plen   uint32
}

func (p *PcapFile) Capture(pkt ...[]byte) error {
	sz := 0
	for _, buf := range pkt {
		sz += len(buf)
	}

	now := time.Now()
	h := phdr{
		sec:    uint32(now.Unix()),
		nsec:   uint32(now.UnixNano() / (1000 * 1000 * 1000)),
		caplen: uint32(sz),
		plen:   uint32(sz),
	}

	if err := binary.Write(p.fp, binary.LittleEndian, &h); err != nil {
		return err
	}

	for _, buf := range pkt {
		n, err := p.fp.Write(buf)
		if err != nil {
			return err
		}
		if n != len(buf) {
			return fmt.Errorf("short write %d of %d", n, len(buf))
		}
	}
	return nil
}

func (p *PcapFile) Close() error {
	return p.fp.Close()
}
