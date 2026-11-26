package iwan

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// ClientConfig configures a single iWAN tunnel session.
type ClientConfig struct {
	Username         string
	Password         string
	MTU              uint16
	Encrypt          bool
	PipeID           uint16
	PipeIdx          uint16
	SRLinks          []netip.Addr
	SRPassword       string
	SREncryptMode    uint8
	HandshakeTimeout time.Duration
	EchoInterval     time.Duration
	DataTimeout      time.Duration
}

// Client manages one authenticated iWAN UDP session.
type Client struct {
	cfg  ClientConfig
	conn net.Conn

	xorKey        [8]byte
	srDecryptBlk  cipher.Block
	srEncryptMode uint8

	token       [2]byte
	sessionID   [4]byte
	encrypt     bool
	effectiveMT uint16
	peerIP      netip.Addr
	dns         []netip.Addr

	wmu    sync.Mutex
	txBuf  []byte
	closed atomic.Bool

	lastRecv atomic.Int64 // UnixNano
	curDelay atomic.Uint32
	minDelay atomic.Uint32
	maxDelay atomic.Uint32

	frags fragReassembler
	rxBuf []byte
}

// NewClient creates a new iWAN protocol client over an already-dialed UDP net.Conn.
func NewClient(cfg ClientConfig, conn net.Conn) (*Client, error) {
	if conn == nil {
		return nil, errors.New("iwan: nil connection")
	}
	if cfg.MTU == 0 {
		cfg.MTU = DefaultMTU
	}
	if cfg.MTU < MinMTU || cfg.MTU > MaxMTU {
		return nil, fmt.Errorf("iwan: mtu %d out of range [%d, %d]", cfg.MTU, MinMTU, MaxMTU)
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if cfg.EchoInterval <= 0 {
		cfg.EchoInterval = DefaultEchoInterval
	}
	if cfg.DataTimeout <= 0 {
		cfg.DataTimeout = DefaultDataTimeout
	}
	srMode := cfg.SREncryptMode
	if srMode == 2 {
		srMode = 1
	}

	c := &Client{
		cfg:           cfg,
		conn:          conn,
		xorKey:        DeriveXORKey(cfg.Username, cfg.Password),
		srDecryptBlk:  newSRDecryptCipher(cfg.SRLinks, cfg.SRPassword, srMode),
		srEncryptMode: srMode,
		txBuf:         make([]byte, 0, MaxMTU+HeaderSize),
		rxBuf:         make([]byte, 4096),
	}
	c.minDelay.Store(5_000_000)
	return c, nil
}

// Handshake performs the OPEN -> OPENACK negotiation with periodic retries.
func (c *Client) Handshake(ctx context.Context) (*HandshakeResult, error) {
	openPkt, err := BuildOpenPacket(&c.cfg)
	if err != nil {
		return nil, err
	}

	hsCtx := ctx
	var cancel context.CancelFunc
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		hsCtx, cancel = context.WithTimeout(ctx, c.cfg.HandshakeTimeout)
		defer cancel()
	}

	// Send initial OPEN immediately.
	if err := c.writeRaw(openPkt); err != nil {
		return nil, fmt.Errorf("iwan: send OPEN: %w", err)
	}

	// Retry OPEN every AuthRetryInterval until handshake succeeds or cancels.
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(AuthRetryInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-hsCtx.Done():
				_ = c.conn.SetReadDeadline(time.Now())
				return
			case <-ticker.C:
				_ = c.writeRaw(openPkt)
			}
		}
	}()

	if deadline, ok := hsCtx.Deadline(); ok {
		_ = c.conn.SetReadDeadline(deadline)
		defer func() { _ = c.conn.SetReadDeadline(time.Time{}) }()
	}

	buf := make([]byte, 2048)
	for {
		n, err := c.conn.Read(buf)
		if err != nil {
			if hsCtx.Err() != nil {
				return nil, fmt.Errorf("iwan: handshake timeout: %w", hsCtx.Err())
			}
			return nil, fmt.Errorf("iwan: read handshake response: %w", err)
		}
		if n < HeaderSize {
			continue
		}
		switch buf[0] {
		case PacketOpenReject:
			return nil, ErrAuthRejected
		case PacketOpenAck:
			ack, err := ParseOpenAck(buf[:n])
			if err != nil {
				continue
			}
			effMTU := c.cfg.MTU
			if ack.MTU >= MinMTU && ack.MTU < effMTU {
				effMTU = ack.MTU
			}
			ack.MTU = effMTU

			c.token = ack.Token
			c.sessionID = ack.SessionID
			c.encrypt = ack.Encrypt
			c.effectiveMT = effMTU
			c.peerIP = ack.PeerIP
			c.dns = ack.DNS
			c.lastRecv.Store(time.Now().UnixNano())
			return ack, nil
		}
	}
}

func (c *Client) writeRaw(pkt []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed.Load() {
		return net.ErrClosed
	}
	_, err := c.conn.Write(pkt)
	return err
}

// WriteIPPacket encapsulates and sends one raw IP packet over the tunnel.
func (c *Client) WriteIPPacket(packet []byte) error {
	if len(packet) == 0 {
		return nil
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed.Load() {
		return net.ErrClosed
	}
	c.txBuf = BuildDataPacket(c.txBuf[:0], c.token, c.sessionID, packet, c.encrypt, c.xorKey)
	_, err := c.conn.Write(c.txBuf)
	return err
}

// WriteEcho sends a signed PKT_ECHOREQ keepalive datagram.
func (c *Client) WriteEcho() error {
	nowMicros := uint64(time.Now().UnixMicro())
	pkt := BuildEchoReq(
		c.token,
		c.sessionID,
		nowMicros,
		c.curDelay.Load(),
		c.minDelay.Load(),
		c.maxDelay.Load(),
		0,
	)
	return c.writeRaw(pkt)
}

// ReadIPPacket blocks until a complete IP packet is received from the peer,
// transparently handling ECHO responses, IPFRAG reassembly, SEGRT, and CLOSE.
func (c *Client) ReadIPPacket(ctx context.Context) ([]byte, error) {
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		n, err := c.conn.Read(c.rxBuf)
		if err != nil {
			return nil, err
		}
		if n < HeaderSize {
			continue
		}
		pkt := c.rxBuf[:n]
		now := time.Now()

		switch pkt[0] {
		case PacketData, PacketDataEnc:
			if n <= HeaderSize {
				continue
			}
			payload := make([]byte, n-HeaderSize)
			copy(payload, pkt[HeaderSize:])
			if pkt[0] == PacketDataEnc {
				XORData(c.xorKey, payload)
			}
			c.lastRecv.Store(now.UnixNano())
			return payload, nil

		case PacketEchoResp:
			if !VerifyPacket(pkt) {
				continue
			}
			c.lastRecv.Store(now.UnixNano())
			if len(pkt) >= SignedHeaderSize+8 {
				sent := binary.LittleEndian.Uint64(pkt[SignedHeaderSize : SignedHeaderSize+8])
				nowMicros := uint64(now.UnixMicro())
				if nowMicros >= sent {
					delay := uint32(nowMicros - sent)
					c.curDelay.Store(delay)
					if delay > c.maxDelay.Load() {
						c.maxDelay.Store(delay)
					}
					if delay < c.minDelay.Load() {
						c.minDelay.Store(delay)
					}
				}
			}

		case PacketIPFrag:
			assembled, accepted := c.frags.handle(pkt, c.encrypt, c.xorKey, now)
			if accepted {
				c.lastRecv.Store(now.UnixNano())
			}
			if len(assembled) > 0 {
				return assembled, nil
			}

		case PacketSegRT:
			payload, accepted := c.handleSegRT(pkt, now)
			if accepted {
				c.lastRecv.Store(now.UnixNano())
			}
			if len(payload) > 0 {
				return payload, nil
			}

		case PacketClose:
			if !VerifyPacket(pkt) {
				continue
			}
			return nil, ErrPeerClosed
		}
	}
}

func (c *Client) handleSegRT(pkt []byte, now time.Time) ([]byte, bool) {
	if len(pkt) < HeaderSize+4 {
		return nil, false
	}
	base := pkt[HeaderSize:]
	linkCnt := int(base[1])
	srHdrLen := linkCnt*4 + 4
	if len(pkt) <= HeaderSize+srHdrLen {
		return nil, false
	}

	inner := append([]byte(nil), pkt[HeaderSize+srHdrLen:]...)
	if len(c.cfg.SRLinks) > 0 && c.srEncryptMode > 0 {
		algo := base[2] & 0x7
		if algo == c.srEncryptMode {
			if !decryptSRBlocks(c.srDecryptBlk, inner) {
				return nil, false
			}
			padLen := int((base[2] >> 3) & 0x1f)
			if padLen > 0 && padLen < len(inner) {
				inner = inner[:len(inner)-padLen]
			}
		} else if algo != 0 {
			return nil, false
		}
	}

	if len(inner) == 0 {
		return nil, false
	}
	if inner[0] == PacketIPFragSR {
		return c.frags.handle(inner, c.encrypt, c.xorKey, now)
	}
	if (inner[0] != PacketData && inner[0] != PacketDataEnc) || len(inner) <= HeaderSize {
		return nil, false
	}
	payload := inner[HeaderSize:]
	if inner[0] == PacketDataEnc {
		XORData(c.xorKey, payload)
	}
	return payload, true
}

// SinceReceive returns the duration since the last valid packet from peer.
func (c *Client) SinceReceive() time.Duration {
	ts := c.lastRecv.Load()
	if ts == 0 {
		return 0
	}
	return time.Since(time.Unix(0, ts))
}

// EffectiveMTU returns the negotiated tunnel MTU.
func (c *Client) EffectiveMTU() uint16 {
	return c.effectiveMT
}

// Close sends a best-effort PKT_CLOSE and closes the underlying UDP socket.
func (c *Client) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	if c.peerIP.IsValid() {
		closePkt := BuildClosePacket(c.token, c.sessionID)
		c.wmu.Lock()
		_ = c.conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = c.conn.Write(closePkt)
		c.wmu.Unlock()
	}
	c.frags.reset()
	return c.conn.Close()
}
