// Package control encodes the tiny TLV control channel that rides inside
// RecControl records.
package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"

	"mirage/internal/proto"
)

// Field is one tag-length-value entry.
type Field struct {
	Tag byte
	Val []byte
}

// Encode serialises fields.
func Encode(fields ...Field) []byte {
	var buf []byte
	for _, f := range fields {
		buf = append(buf, f.Tag)
		var ln [2]byte
		binary.BigEndian.PutUint16(ln[:], uint16(len(f.Val)))
		buf = append(buf, ln[:]...)
		buf = append(buf, f.Val...)
	}
	return buf
}

// Decode parses a control payload.
func Decode(b []byte) ([]Field, error) {
	var out []Field
	i := 0
	for i+3 <= len(b) {
		tag := b[i]
		ln := int(binary.BigEndian.Uint16(b[i+1 : i+3]))
		i += 3
		if i+ln > len(b) {
			return nil, errors.New("control: truncated field")
		}
		out = append(out, Field{Tag: tag, Val: append([]byte(nil), b[i:i+ln]...)})
		i += ln
	}
	if i != len(b) {
		return nil, errors.New("control: trailing bytes")
	}
	return out, nil
}

func find(fields []Field, tag byte) (Field, bool) {
	for _, f := range fields {
		if f.Tag == tag {
			return f, true
		}
	}
	return Field{}, false
}

// Welcome builds the server's first control message.
func Welcome(assignedIP, dns string, mtu int) []byte {
	return Encode(
		Field{Tag: proto.CtrlStatus, Val: []byte("OK")},
		Field{Tag: proto.CtrlAssignedIP, Val: []byte(assignedIP)},
		Field{Tag: proto.CtrlDNS, Val: []byte(dns)},
		Field{Tag: proto.CtrlMTU, Val: []byte(strconv.Itoa(mtu))},
	)
}

// WelcomeInfo is the parsed result of a Welcome message.
type WelcomeInfo struct {
	AssignedIP string
	DNS        string
	MTU        int
}

// ParseWelcome reads what Welcome produced.
func ParseWelcome(b []byte) (*WelcomeInfo, error) {
	fields, err := Decode(b)
	if err != nil {
		return nil, err
	}
	st, ok := find(fields, proto.CtrlStatus)
	if !ok {
		return nil, errors.New("control: welcome without status")
	}
	if string(st.Val) != "OK" {
		if e, ok := find(fields, proto.CtrlError); ok {
			return nil, fmt.Errorf("server refused: %s", string(e.Val))
		}
		return nil, fmt.Errorf("server refused: %s", string(st.Val))
	}
	info := &WelcomeInfo{}
	if f, ok := find(fields, proto.CtrlAssignedIP); ok {
		info.AssignedIP = string(f.Val)
	}
	if f, ok := find(fields, proto.CtrlDNS); ok {
		info.DNS = string(f.Val)
	}
	if f, ok := find(fields, proto.CtrlMTU); ok {
		if m, err := strconv.Atoi(string(f.Val)); err == nil {
			info.MTU = m
		}
	}
	if info.AssignedIP == "" {
		return nil, errors.New("control: welcome without assigned ip")
	}
	return info, nil
}

// Ping builds a keepalive request carrying the current unix time.
func Ping(now int64) []byte {
	return Encode(Field{Tag: proto.CtrlPing, Val: []byte(strconv.FormatInt(now, 10))})
}

// Pong answers a Ping.
func Pong(now int64) []byte {
	return Encode(Field{Tag: proto.CtrlPong, Val: []byte(strconv.FormatInt(now, 10))})
}

// IsPing reports whether the payload is a ping.
func IsPing(b []byte) bool {
	fields, err := Decode(b)
	if err != nil {
		return false
	}
	_, ok := find(fields, proto.CtrlPing)
	return ok
}

// IsPong reports whether the payload is a pong.
func IsPong(b []byte) bool {
	fields, err := Decode(b)
	if err != nil {
		return false
	}
	_, ok := find(fields, proto.CtrlPong)
	return ok
}
