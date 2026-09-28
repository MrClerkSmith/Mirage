package control

import (
	"testing"

	"mirage/internal/proto"
)

func TestWelcomeRoundTrip(t *testing.T) {
	b := Welcome("10.7.0.2/24", "10.7.0.1", 1400)
	info, err := ParseWelcome(b)
	if err != nil {
		t.Fatal(err)
	}
	if info.AssignedIP != "10.7.0.2/24" || info.DNS != "10.7.0.1" || info.MTU != 1400 {
		t.Fatalf("unexpected welcome: %+v", info)
	}
}

func TestRefusal(t *testing.T) {
	b := Encode(
		Field{Tag: proto.CtrlStatus, Val: []byte("NO")},
		Field{Tag: proto.CtrlError, Val: []byte("unauthorized")},
	)
	if _, err := ParseWelcome(b); err == nil {
		t.Fatal("expected a refusal error")
	}
}

func TestPingPong(t *testing.T) {
	if !IsPing(Ping(123)) {
		t.Fatal("IsPing failed")
	}
	if !IsPong(Pong(123)) {
		t.Fatal("IsPong failed")
	}
	if IsPong(Ping(1)) {
		t.Fatal("a ping must not be a pong")
	}
}

func TestDecodeTruncated(t *testing.T) {
	if _, err := Decode([]byte{1, 0, 5}); err == nil {
		t.Fatal("truncated field must error")
	}
	if _, err := Decode(Welcome("a", "b", 1)); err != nil {
		t.Fatal(err)
	}
}
