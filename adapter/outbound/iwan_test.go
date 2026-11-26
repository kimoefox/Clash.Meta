package outbound

import (
	"bytes"
	"context"
	"crypto/subtle"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/iwan"
)

// startIwanLoopbackServer runs a mock iWAN UDP server whose data plane is wired
// to a server-side userspace mipstack (10.20.30.1/32) serving both a TCP echo
// listener and a UDP echo listener on 10.20.30.1:8080.
func startIwanLoopbackServer(t *testing.T, wantUser, wantPass string, allowEncrypt bool) (host string, port int, opens *atomic.Int32, closes *atomic.Int32) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	serverIP := netip.MustParseAddr("10.20.30.1")
	clientIP := netip.MustParseAddr("10.20.30.10")

	stackOpt := IPStackOption{Mode: ipStackMips}
	serverStack, err := newIPStack(stackOpt, []netip.Prefix{netip.PrefixFrom(serverIP, 32)}, 1400)
	if err != nil {
		t.Fatal(err)
	}
	if err := serverStack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverStack.Close() })

	// TCP echo service inside tunnel at 10.20.30.1:8080.
	tcpLn, err := serverStack.ListenTCP(context.Background(), "tcp", netip.AddrPortFrom(serverIP, 8080))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcpLn.Close() })
	go func() {
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()

	// UDP echo service inside tunnel at 10.20.30.1:8080.
	udpSvc, err := serverStack.ListenUDP(context.Background(), "udp", netip.AddrPortFrom(serverIP, 8080))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpSvc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, raddr, err := udpSvc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udpSvc.WriteTo(buf[:n], raddr)
		}
	}()

	expectedPwd, _ := iwan.EncryptPassword(wantUser, wantPass)
	xorKey := iwan.DeriveXORKey(wantUser, wantPass)
	token := [2]byte{0x22, 0x33}
	sessID := [4]byte{0x01, 0x02, 0x03, 0x04}

	opens = &atomic.Int32{}
	closes = &atomic.Int32{}

	type peerState struct {
		addr net.Addr
		enc  bool
	}
	var currentPeer atomic.Pointer[peerState]

	// Pump IP packets from serverStack -> client over iWAN UDP.
	go func() {
		buf := make([]byte, 64*1024)
		bufs := [][]byte{buf}
		sizes := []int{0}
		for {
			_, err := serverStack.Read(bufs, sizes, 0)
			if err != nil {
				return
			}
			if sizes[0] <= 0 {
				continue
			}
			peer := currentPeer.Load()
			if peer == nil {
				continue
			}
			pkt := iwan.BuildDataPacket(nil, token, sessID, buf[:sizes[0]], peer.enc, xorKey)
			_, _ = pc.WriteTo(pkt, peer.addr)
		}
	}()

	// Handle incoming iWAN UDP datagrams from client.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pkt := buf[:n]
			if len(pkt) < iwan.HeaderSize {
				continue
			}
			switch pkt[0] {
			case iwan.PacketOpen:
				if !iwan.VerifyPacket(pkt) {
					continue
				}
				var user string
				var pwd [16]byte
				reqEnc := pkt[1] != 0
				data := pkt[iwan.SignedHeaderSize:]
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
					rej := make([]byte, iwan.SignedHeaderSize)
					rej[0] = iwan.PacketOpenReject
					iwan.SignPacket(rej)
					_, _ = pc.WriteTo(rej, addr)
					continue
				}
				enc := reqEnc && allowEncrypt
				currentPeer.Store(&peerState{addr: addr, enc: enc})
				opens.Add(1)

				ack := make([]byte, iwan.SignedHeaderSize, 64)
				ack[0] = iwan.PacketOpenAck
				if enc {
					ack[1] = 1
				}
				copy(ack[2:4], token[:])
				copy(ack[4:8], sessID[:])
				iwan.SignPacket(ack)
				// TLV 3: MTU=1400
				ack = append(ack, 3, 4, byte(1400>>8), byte(1400&0xff))
				// TLV 4: client IP
				a4 := clientIP.As4()
				ack = append(ack, 4, 6, a4[0], a4[1], a4[2], a4[3])
				// TLV 8: encrypt
				if enc {
					ack = append(ack, 8, 3, 1)
				} else {
					ack = append(ack, 8, 3, 0)
				}
				_, _ = pc.WriteTo(ack, addr)

			case iwan.PacketEchoReq:
				if !iwan.VerifyPacket(pkt) {
					continue
				}
				resp := append([]byte(nil), pkt...)
				resp[0] = iwan.PacketEchoResp
				iwan.SignPacket(resp)
				_, _ = pc.WriteTo(resp, addr)

			case iwan.PacketData, iwan.PacketDataEnc:
				payload := append([]byte(nil), pkt[iwan.HeaderSize:]...)
				if pkt[0] == iwan.PacketDataEnc {
					iwan.XORData(xorKey, payload)
				}
				_, _ = serverStack.Write([][]byte{payload}, 0)

			case iwan.PacketClose:
				if iwan.VerifyPacket(pkt) {
					closes.Add(1)
				}
			}
		}
	}()

	h, pStr, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(pStr)
	if err != nil {
		t.Fatal(err)
	}
	return h, p, opens, closes
}

func TestIwanOutboundTCPUDPAndCloseIdle(t *testing.T) {
	for _, encrypt := range []bool{false, true} {
		name := "plain"
		if encrypt {
			name = "encrypted"
		}
		t.Run(name, func(t *testing.T) {
			host, port, opens, closes := startIwanLoopbackServer(t, "myuser", "mypassword", true)

			proxy, err := NewIwan(IwanOption{
				Name:     "iwan",
				Server:   host,
				Port:     port,
				Username: "myuser",
				Password: "mypassword",
				MTU:      1400,
				Encrypt:  encrypt,
				UDP:      true,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()

			if proxy.Type() != C.Iwan {
				t.Fatalf("Type() = %v, want Iwan", proxy.Type())
			}
			if !proxy.IsL3Protocol(nil) {
				t.Fatal("IsL3Protocol() = false, want true")
			}
			// Lazy connect: zero handshakes before first dial.
			if opens.Load() != 0 {
				t.Fatalf("expected lazy init with 0 opens, got %d", opens.Load())
			}

			// 1. TCP round-trip through mipstack + iWAN tunnel.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			tcpMeta := &C.Metadata{
				NetWork: C.TCP,
				Type:    C.SOCKS5,
				DstIP:   netip.MustParseAddr("10.20.30.1"),
				DstPort: 8080,
			}
			conn, err := proxy.DialContext(ctx, tcpMeta)
			if err != nil {
				t.Fatalf("DialContext failed: %v", err)
			}
			payload := bytes.Repeat([]byte("iwan-tcp-test!"), 50)
			if _, err := conn.Write(payload); err != nil {
				t.Fatalf("tcp write: %v", err)
			}
			got := make([]byte, len(payload))
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatalf("tcp read: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("tcp echo mismatch")
			}
			_ = conn.Close()

			// 2. UDP round-trip through mipstack + iWAN tunnel.
			udpMeta := &C.Metadata{
				NetWork: C.UDP,
				Type:    C.SOCKS5,
				DstIP:   netip.MustParseAddr("10.20.30.1"),
				DstPort: 8080,
			}
			pc, err := proxy.ListenPacketContext(ctx, udpMeta)
			if err != nil {
				t.Fatalf("ListenPacketContext failed: %v", err)
			}
			udpPayload := []byte("iwan-udp-echo-datagram")
			dstAddr := &net.UDPAddr{IP: net.IPv4(10, 20, 30, 1), Port: 8080}
			if _, err := pc.WriteTo(udpPayload, dstAddr); err != nil {
				t.Fatalf("udp write: %v", err)
			}
			udpBuf := make([]byte, 1024)
			_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, _, err := pc.ReadFrom(udpBuf)
			if err != nil {
				t.Fatalf("udp read: %v", err)
			}
			if !bytes.Equal(udpBuf[:n], udpPayload) {
				t.Fatalf("udp echo mismatch: got %q, want %q", udpBuf[:n], udpPayload)
			}
			_ = pc.Close()

			if opens.Load() != 1 {
				t.Fatalf("expected 1 session open, got %d", opens.Load())
			}

			// 3. CloseIdle tears down the idle session and sends PKT_CLOSE.
			proxy.CloseIdle()
			deadline := time.Now().Add(2 * time.Second)
			for closes.Load() == 0 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if closes.Load() != 1 {
				t.Fatalf("expected server to receive PKT_CLOSE after CloseIdle, got %d", closes.Load())
			}

			// 4. Subsequent dial transparently reconnects.
			conn2, err := proxy.DialContext(ctx, tcpMeta)
			if err != nil {
				t.Fatalf("reconnect DialContext failed: %v", err)
			}
			msg2 := []byte("reconnected-ok")
			if _, err := conn2.Write(msg2); err != nil {
				t.Fatal(err)
			}
			got2 := make([]byte, len(msg2))
			_ = conn2.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(conn2, got2); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got2, msg2) {
				t.Fatalf("reconnect mismatch: got %q", got2)
			}
			_ = conn2.Close()

			if opens.Load() != 2 {
				t.Fatalf("expected 2 session opens after reconnect, got %d", opens.Load())
			}
		})
	}
}
