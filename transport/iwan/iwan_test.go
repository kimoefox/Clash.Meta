package iwan

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestOpenPacketAndSignature(t *testing.T) {
	cfg := &ClientConfig{
		Username: "myuser",
		Password: "mypassword",
		MTU:      1400,
		Encrypt:  true,
		PipeID:   7,
		PipeIdx:  1,
	}
	pkt, err := BuildOpenPacket(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if pkt[0] != PacketOpen || pkt[1] != 1 {
		t.Fatalf("unexpected header: %x", pkt[:HeaderSize])
	}
	if !VerifyPacket(pkt) {
		t.Fatal("VerifyPacket failed on valid OPEN packet")
	}

	// Verify TLV parsing matches iwand server expectations.
	expectedPwd, err := EncryptPassword("myuser", "mypassword")
	if err != nil {
		t.Fatal(err)
	}
	var gotUser string
	var gotMTU uint16
	var gotEnc byte
	var gotPipe uint16
	var gotPwd [16]byte
	data := pkt[SignedHeaderSize:]
	for len(data) > 0 {
		typ := data[0]
		tlen := int(data[1])
		val := data[2:tlen]
		switch typ {
		case 1:
			gotUser = string(val)
		case 2:
			copy(gotPwd[:], val)
		case 3:
			gotMTU = binary.BigEndian.Uint16(val)
		case 8:
			gotEnc = val[0]
		case 0x0a:
			gotPipe = binary.BigEndian.Uint16(val)
		}
		data = data[tlen:]
	}
	if gotUser != "myuser" || gotMTU != 1400 || gotEnc != 1 {
		t.Fatalf("parsed TLVs mismatch: user=%q mtu=%d enc=%d", gotUser, gotMTU, gotEnc)
	}
	if subtle.ConstantTimeCompare(gotPwd[:], expectedPwd[:]) != 1 {
		t.Fatal("password block mismatch")
	}
	if wantPipe := uint16(7 | (1 << 15)); gotPipe != wantPipe {
		t.Fatalf("pipe TLV = 0x%04x, want 0x%04x", gotPipe, wantPipe)
	}
}

func TestFragReassembler(t *testing.T) {
	var r fragReassembler
	key := DeriveXORKey("alice", "secret")
	plain := bytes.Repeat([]byte("ABCDEFGH"), 25) // 200 bytes
	wire := append([]byte(nil), plain...)
	XORData(key, wire)

	buildFrag := func(fragID uint32, off, length int, eop bool, body []byte) []byte {
		pkt := make([]byte, HeaderSize+EthPktSize+len(body))
		pkt[0] = PacketIPFrag
		binary.LittleEndian.PutUint32(pkt[HeaderSize+8:HeaderSize+12], fragID)
		var bf uint32
		if eop {
			bf |= 1
		}
		bf |= uint32(off&0x1fff) << 2
		bf |= uint32(length&0x7ff) << 15
		binary.LittleEndian.PutUint32(pkt[HeaderSize+12:HeaderSize+16], bf)
		copy(pkt[HeaderSize+EthPktSize:], body)
		return pkt
	}

	now := time.Now()
	if out, ok := r.handle(buildFrag(42, 0, 100, false, wire[:100]), true, key, now); !ok || out != nil {
		t.Fatalf("first fragment: out=%v ok=%v", out, ok)
	}
	out, ok := r.handle(buildFrag(42, 100, 100, true, wire[100:]), true, key, now)
	if !ok || !bytes.Equal(out, plain) {
		t.Fatalf("reassembled mismatch: ok=%v len=%d", ok, len(out))
	}
}

func startMockIwanServer(t *testing.T, wantUser, wantPass string, allowEncrypt bool, assignIP netip.Addr) (string, <-chan struct{}) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	closedCh := make(chan struct{}, 1)
	expectedPwd, _ := EncryptPassword(wantUser, wantPass)
	xorKey := DeriveXORKey(wantUser, wantPass)
	token := [2]byte{0x12, 0x34}
	sessID := [4]byte{0xaa, 0xbb, 0xcc, 0xdd}

	go func() {
		buf := make([]byte, 4096)
		var enc bool
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pkt := buf[:n]
			if len(pkt) < HeaderSize {
				continue
			}
			switch pkt[0] {
			case PacketOpen:
				if !VerifyPacket(pkt) {
					continue
				}
				var user string
				var pwd [16]byte
				reqEnc := pkt[1] != 0
				data := pkt[SignedHeaderSize:]
				for len(data) >= 2 {
					tlen := int(data[1])
					val := data[2:tlen]
					switch data[0] {
					case 1:
						user = string(val)
					case 2:
						copy(pwd[:], val)
					case 8:
						if len(val) > 0 {
							reqEnc = val[0] != 0
						}
					}
					data = data[tlen:]
				}
				if user != wantUser || subtle.ConstantTimeCompare(pwd[:], expectedPwd[:]) != 1 {
					rej := make([]byte, SignedHeaderSize)
					rej[0] = PacketOpenReject
					SignPacket(rej)
					_, _ = pc.WriteTo(rej, addr)
					continue
				}
				enc = reqEnc && allowEncrypt
				ack := make([]byte, SignedHeaderSize, 64)
				ack[0] = PacketOpenAck
				if enc {
					ack[1] = 1
				}
				copy(ack[2:4], token[:])
				copy(ack[4:8], sessID[:])
				SignPacket(ack)
				ack = appendTLV(ack, 3, byte(1380>>8), byte(1380&0xff))
				a4 := assignIP.As4()
				ack = appendTLV(ack, 4, a4[:]...)
				ack = appendTLV(ack, 5, 1, 1, 1, 1)
				if enc {
					ack = appendTLV(ack, 8, 1)
				} else {
					ack = appendTLV(ack, 8, 0)
				}
				_, _ = pc.WriteTo(ack, addr)

			case PacketEchoReq:
				if !VerifyPacket(pkt) {
					continue
				}
				resp := make([]byte, len(pkt))
				copy(resp, pkt)
				resp[0] = PacketEchoResp
				SignPacket(resp)
				_, _ = pc.WriteTo(resp, addr)

			case PacketData, PacketDataEnc:
				payload := append([]byte(nil), pkt[HeaderSize:]...)
				if pkt[0] == PacketDataEnc {
					XORData(xorKey, payload)
				}
				reply := BuildDataPacket(nil, token, sessID, payload, enc, xorKey)
				_, _ = pc.WriteTo(reply, addr)

			case PacketClose:
				if VerifyPacket(pkt) {
					select {
					case closedCh <- struct{}{}:
					default:
					}
				}
			}
		}
	}()
	return pc.LocalAddr().String(), closedCh
}

func TestClientHandshakeEchoDataClose(t *testing.T) {
	for _, encrypt := range []bool{false, true} {
		name := "plain"
		if encrypt {
			name = "encrypted"
		}
		t.Run(name, func(t *testing.T) {
			addr, closedCh := startMockIwanServer(t, "alice", "secret", true, netip.MustParseAddr("10.20.30.10"))
			conn, err := net.Dial("udp", addr)
			if err != nil {
				t.Fatal(err)
			}
			client, err := NewClient(ClientConfig{
				Username: "alice",
				Password: "secret",
				MTU:      1400,
				Encrypt:  encrypt,
			}, conn)
			if err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			ack, err := client.Handshake(ctx)
			if err != nil {
				t.Fatalf("Handshake failed: %v", err)
			}
			if ack.PeerIP != netip.MustParseAddr("10.20.30.10") || ack.MTU != 1380 || ack.Encrypt != encrypt {
				t.Fatalf("unexpected ack: %+v", ack)
			}
			if len(ack.DNS) != 1 || ack.DNS[0] != netip.MustParseAddr("1.1.1.1") {
				t.Fatalf("unexpected DNS: %v", ack.DNS)
			}

			if err := client.WriteEcho(); err != nil {
				t.Fatal(err)
			}
			want := []byte("hello-iwan-ip-payload")
			if err := client.WriteIPPacket(want); err != nil {
				t.Fatal(err)
			}
			got, err := client.ReadIPPacket(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("echo mismatch: got %q, want %q", got, want)
			}

			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-closedCh:
			case <-time.After(time.Second):
				t.Fatal("expected server to receive PKT_CLOSE")
			}
		})
	}
}

func TestClientAuthRejected(t *testing.T) {
	addr, _ := startMockIwanServer(t, "alice", "correct", false, netip.MustParseAddr("10.20.30.10"))
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ClientConfig{
		Username: "alice",
		Password: "wrong",
		MTU:      1400,
	}, conn)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = client.Handshake(ctx)
	if !errors.Is(err, ErrAuthRejected) {
		t.Fatalf("err = %v, want ErrAuthRejected", err)
	}
}
