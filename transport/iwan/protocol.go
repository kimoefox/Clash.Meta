package iwan

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Packet types matching Panabit iWAN / Ricky-Hao/iwand.
const (
	PacketOpenReject byte = 0x11
	PacketOpenAck    byte = 0x12
	PacketOpen       byte = 0x13
	PacketData       byte = 0x14
	PacketEchoReq    byte = 0x15
	PacketEchoResp   byte = 0x16
	PacketClose      byte = 0x17
	PacketDataEnc    byte = 0x18
	PacketIPFrag     byte = 0x21
	PacketIPFragSR   byte = 0x22
	PacketSegRT      byte = 0x27
)

const (
	HeaderSize       = 8
	SignSize         = 16
	SignedHeaderSize = HeaderSize + SignSize
	EthPktSize       = 16

	DefaultMTU = 1400
	MinMTU     = 68
	MaxMTU     = 1600

	DefaultHandshakeTimeout = 6 * time.Second
	AuthRetryInterval       = 2 * time.Second
	DefaultEchoInterval     = 2 * time.Second
	DefaultDataTimeout      = 15 * time.Second

	fragSlots      = 10
	fragBufSize    = 2048
	fragMaxContent = 4096
	fragTimeout    = 5 * time.Second
)

var (
	signMagic = []byte("mw")

	ErrAuthRejected = errors.New("iwan: authentication rejected by server")
	ErrPeerClosed   = errors.New("iwan: session closed by peer")
)

// HandshakeResult holds the tunnel parameters negotiated in OPENACK.
type HandshakeResult struct {
	Token      [2]byte
	SessionID  [4]byte
	PeerIP     netip.Addr
	MTU        uint16
	DNS        []netip.Addr
	Encrypt    bool
	PeerDupPkt byte
}

// SignPacket computes MD5(packet[0:8] || "mw") and writes it to packet[8:24].
func SignPacket(packet []byte) {
	h := md5.New()
	_, _ = h.Write(packet[:HeaderSize])
	_, _ = h.Write(signMagic)
	copy(packet[HeaderSize:SignedHeaderSize], h.Sum(nil))
}

// VerifyPacket checks the MD5 control packet signature at packet[8:24].
func VerifyPacket(packet []byte) bool {
	if len(packet) < SignedHeaderSize {
		return false
	}
	h := md5.New()
	_, _ = h.Write(packet[:HeaderSize])
	_, _ = h.Write(signMagic)
	return bytes.Equal(packet[HeaderSize:SignedHeaderSize], h.Sum(nil))
}

// EncryptPassword computes the 16-byte AES-128-ECB password TLV block.
// Key is MD5("mw" + username); plaintext is zero-padded/truncated to 16 bytes.
func EncryptPassword(username, password string) ([16]byte, error) {
	keyBuf := make([]byte, 0, len(signMagic)+len(username))
	keyBuf = append(keyBuf, signMagic...)
	keyBuf = append(keyBuf, username...)
	key := md5.Sum(keyBuf)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return [16]byte{}, err
	}
	var plain, encrypted [16]byte
	copy(plain[:], password)
	block.Encrypt(encrypted[:], plain[:])
	return encrypted, nil
}

// DeriveXORKey derives the 8-byte repeating XOR key: MD5(username + password)[0:8].
func DeriveXORKey(username, password string) [8]byte {
	sum := md5.Sum([]byte(username + password))
	var key [8]byte
	copy(key[:], sum[:8])
	return key
}

// XORData applies the 8-byte repeating XOR key in place.
func XORData(key [8]byte, data []byte) {
	for i := range data {
		data[i] ^= key[i&7]
	}
}

func appendTLV(dst []byte, tlvType byte, val ...byte) []byte {
	dst = append(dst, tlvType, byte(len(val)+2))
	return append(dst, val...)
}

// BuildOpenPacket constructs a signed PKT_OPEN authentication packet.
func BuildOpenPacket(cfg *ClientConfig) ([]byte, error) {
	if cfg.Username == "" {
		return nil, errors.New("iwan: empty username")
	}
	if len(cfg.Username)+2 > 255 {
		return nil, errors.New("iwan: username too long")
	}
	if cfg.Password == "" {
		return nil, errors.New("iwan: empty password")
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}
	if mtu < MinMTU || mtu > MaxMTU {
		return nil, fmt.Errorf("iwan: mtu %d out of range [%d, %d]", mtu, MinMTU, MaxMTU)
	}

	encPwd, err := EncryptPassword(cfg.Username, cfg.Password)
	if err != nil {
		return nil, err
	}

	pkt := make([]byte, SignedHeaderSize, 96)
	pkt[0] = PacketOpen
	if cfg.Encrypt {
		pkt[1] = 1
	}
	SignPacket(pkt)

	// TLV 3: MTU (uint16 big-endian)
	pkt = appendTLV(pkt, 3, byte(mtu>>8), byte(mtu))
	// TLV 1: username
	pkt = appendTLV(pkt, 1, []byte(cfg.Username)...)
	// TLV 2: AES-128-ECB encrypted password block (16 bytes)
	pkt = appendTLV(pkt, 2, encPwd[:]...)
	// TLV 8: encrypt mode (only emitted when enabled, matching iwand.c)
	if cfg.Encrypt {
		pkt = appendTLV(pkt, 8, 1)
	}
	// TLV 0x0a: optional pipeid / pipeidx
	if cfg.PipeID != 0 || cfg.PipeIdx != 0 {
		val := uint32(cfg.PipeID) | (uint32(cfg.PipeIdx) << 15)
		pkt = appendTLV(pkt, 0x0a, byte(val>>8), byte(val))
	}
	return pkt, nil
}

// ParseOpenAck validates and decodes a PKT_OPENACK response packet.
func ParseOpenAck(pkt []byte) (*HandshakeResult, error) {
	if len(pkt) < SignedHeaderSize {
		return nil, errors.New("iwan: short OPENACK packet")
	}
	if pkt[0] != PacketOpenAck {
		return nil, fmt.Errorf("iwan: unexpected packet type 0x%02x", pkt[0])
	}
	if !VerifyPacket(pkt) {
		return nil, errors.New("iwan: invalid OPENACK signature")
	}

	res := &HandshakeResult{
		Encrypt: pkt[1] != 0,
	}
	copy(res.Token[:], pkt[2:4])
	copy(res.SessionID[:], pkt[4:8])

	data := pkt[SignedHeaderSize:]
	for len(data) >= 2 {
		typ := data[0]
		tlen := int(data[1])
		if tlen < 2 || tlen > len(data) {
			break
		}
		val := data[2:tlen]
		switch typ {
		case 3: // MTU
			if len(val) >= 2 {
				res.MTU = binary.BigEndian.Uint16(val[:2])
			}
		case 4: // Peer IPv4
			if len(val) >= 4 {
				res.PeerIP = netip.AddrFrom4([4]byte(val[:4]))
			}
		case 5: // DNS0
			if len(val) >= 4 {
				ip := netip.AddrFrom4([4]byte(val[:4]))
				if ip.IsValid() && !ip.IsUnspecified() {
					res.DNS = []netip.Addr{ip}
				}
			}
		case 6: // DNS0 + DNS1
			var dnsList []netip.Addr
			if len(val) >= 4 {
				ip := netip.AddrFrom4([4]byte(val[:4]))
				if ip.IsValid() && !ip.IsUnspecified() {
					dnsList = append(dnsList, ip)
				}
			}
			if len(val) >= 8 {
				ip := netip.AddrFrom4([4]byte(val[4:8]))
				if ip.IsValid() && !ip.IsUnspecified() {
					dnsList = append(dnsList, ip)
				}
			}
			if len(dnsList) > 0 {
				res.DNS = dnsList
			}
		case 7: // peer dup pkt flag
			if len(val) >= 1 {
				res.PeerDupPkt = val[0]
			}
		case 8: // encrypt flag
			if len(val) >= 1 {
				res.Encrypt = val[0] != 0
			}
		}
		data = data[tlen:]
	}

	if !res.PeerIP.IsValid() || res.PeerIP.IsUnspecified() {
		return nil, errors.New("iwan: OPENACK missing valid peer IP")
	}
	return res, nil
}

// BuildEchoReq builds the 60-byte signed PKT_ECHOREQ keepalive packet.
func BuildEchoReq(token [2]byte, sessionID [4]byte, nowMicros uint64, curDelay, minDelay, maxDelay, rtMagic uint32) []byte {
	pkt := make([]byte, SignedHeaderSize+36)
	pkt[0] = PacketEchoReq
	copy(pkt[2:4], token[:])
	copy(pkt[4:8], sessionID[:])
	SignPacket(pkt)

	p := pkt[SignedHeaderSize:]
	binary.LittleEndian.PutUint64(p[0:8], nowMicros)
	binary.LittleEndian.PutUint32(p[8:12], curDelay)
	binary.LittleEndian.PutUint32(p[12:16], minDelay)
	binary.LittleEndian.PutUint32(p[16:20], maxDelay)
	// p[20:24] = zeros
	p[24], p[25], p[26], p[27] = 'T', 'D', 'R', 0
	binary.BigEndian.PutUint32(p[28:32], rtMagic)
	// p[32:36] = zeros
	return pkt
}

// BuildClosePacket builds a 24-byte signed PKT_CLOSE packet.
func BuildClosePacket(token [2]byte, sessionID [4]byte) []byte {
	pkt := make([]byte, SignedHeaderSize)
	pkt[0] = PacketClose
	copy(pkt[2:4], token[:])
	copy(pkt[4:8], sessionID[:])
	SignPacket(pkt)
	return pkt
}

// BuildDataPacket writes a PKT_DATA or PKT_DATA_ENC datagram into dst (reusing
// dst capacity when large enough) and returns the resulting slice.
func BuildDataPacket(dst []byte, token [2]byte, sessionID [4]byte, payload []byte, encrypt bool, key [8]byte) []byte {
	total := HeaderSize + len(payload)
	if cap(dst) < total {
		dst = make([]byte, total)
	} else {
		dst = dst[:total]
	}
	if encrypt {
		dst[0] = PacketDataEnc
		dst[1] = 1
	} else {
		dst[0] = PacketData
		dst[1] = 0
	}
	copy(dst[2:4], token[:])
	copy(dst[4:8], sessionID[:])
	copy(dst[HeaderSize:], payload)
	if encrypt {
		XORData(key, dst[HeaderSize:])
	}
	return dst
}

// fragSlot tracks one in-progress IPFRAG reassembly matching iwand.c.
type fragSlot struct {
	buf       [fragBufSize]byte
	timestamp time.Time
	id        uint32
	off       uint16
	length    uint16
	inUse     bool
}

type fragReassembler struct {
	slots [fragSlots]fragSlot
}

func (r *fragReassembler) reset() {
	for i := range r.slots {
		r.slots[i].inUse = false
	}
}

// handle ingests one PKT_IPFRAG / PKT_IPFRAG_SR packet. When reassembly
// completes, it returns the complete IP packet (decrypted if encrypt is true)
// and accepted=true. Intermediate accepted fragments return (nil, true).
func (r *fragReassembler) handle(pkt []byte, encrypt bool, xorKey [8]byte, now time.Time) (assembled []byte, accepted bool) {
	if len(pkt) < HeaderSize+EthPktSize {
		return nil, false
	}
	ethpkt := pkt[HeaderSize : HeaderSize+EthPktSize]
	fragID := binary.LittleEndian.Uint32(ethpkt[8:12])
	bf := binary.LittleEndian.Uint32(ethpkt[12:16])

	eop := (bf & 0x1) != 0
	fragOff := int((bf >> 2) & 0x1fff)
	fragLen := int((bf >> 15) & 0x7ff)

	if fragLen == 0 || len(pkt) != HeaderSize+EthPktSize+fragLen {
		return nil, false
	}
	fragData := pkt[HeaderSize+EthPktSize:]

	// Search for existing matching slot.
	for i := range r.slots {
		s := &r.slots[i]
		if !s.inUse || s.id != fragID {
			continue
		}
		if now.Sub(s.timestamp) >= fragTimeout {
			s.inUse = false
			break
		}

		var totalLen int
		var content []byte
		if !eop {
			totalLen = int(s.length) + fragLen
			if totalLen > fragMaxContent {
				s.inUse = false
				return nil, false
			}
			content = make([]byte, totalLen)
			copy(content, fragData)
			copy(content[fragLen:], s.buf[:s.length])
		} else {
			totalLen = fragOff + fragLen
			if totalLen < int(s.length) {
				totalLen = int(s.length)
			}
			if totalLen > fragMaxContent {
				s.inUse = false
				return nil, false
			}
			content = make([]byte, totalLen)
			copy(content, s.buf[:s.length])
			copy(content[fragOff:], fragData)
		}

		if eop {
			if encrypt {
				XORData(xorKey, content)
			}
			s.inUse = false
			return content, true
		}

		if totalLen > fragBufSize {
			s.inUse = false
			return nil, false
		}
		copy(s.buf[:], content)
		s.length = uint16(totalLen)
		s.timestamp = now
		return nil, true
	}

	// Single-fragment packet with eop set directly (edge case).
	if eop && fragOff == 0 {
		out := append([]byte(nil), fragData...)
		if encrypt {
			XORData(xorKey, out)
		}
		return out, true
	}

	// Allocate an empty or expired slot.
	slotIdx := -1
	for i := range r.slots {
		if !r.slots[i].inUse || now.Sub(r.slots[i].timestamp) >= fragTimeout {
			slotIdx = i
			break
		}
	}
	if slotIdx < 0 || fragLen > fragBufSize {
		return nil, false
	}
	s := &r.slots[slotIdx]
	s.inUse = true
	s.id = fragID
	s.timestamp = now
	s.off = uint16(fragOff)
	s.length = uint16(fragLen)
	copy(s.buf[:], fragData)
	return nil, true
}

func newSRDecryptCipher(srLinks []netip.Addr, srPassword string, srEncryptMode uint8) cipher.Block {
	if len(srLinks) == 0 || srEncryptMode == 0 {
		return nil
	}
	var keyBuf [128]byte
	n := copy(keyBuf[:], srPassword)
	for _, ip := range srLinks {
		if !ip.Is4() || n+4 > len(keyBuf) {
			break
		}
		a4 := ip.As4()
		copy(keyBuf[n:n+4], a4[:])
		n += 4
	}
	// iwand.c uses AES-128 (first 16 bytes, falling back from mode 2 to 1).
	blk, err := aes.NewCipher(keyBuf[:16])
	if err != nil {
		return nil
	}
	return blk
}

func decryptSRBlocks(blk cipher.Block, data []byte) bool {
	const blockSize = aes.BlockSize
	if blk == nil || len(data)%blockSize != 0 {
		return false
	}
	for off := 0; off < len(data); off += blockSize {
		blk.Decrypt(data[off:off+blockSize], data[off:off+blockSize])
	}
	return true
}
