package ninja

// Pass layer of the ninja tunnel (outer layer, above core.go).
//
// Stack: raw (TLS/WS) -> PassConn -> Conn (core) -> socks address + payload.
//
//	psk   = SHA3-512(password)[:keyLen]
//	token = HKDF-SHA3-512(secret=psk, salt=const32, info=password, 16)
//	key   = HKDF-SHA3-512(secret=psk, salt=salt12, info=const32, keyLen)
//
// Each direction opens with a 12 byte random salt in clear. Every record is
//
//	seal( BE16(len ^ m1) || BE16(pad ^ m2) ) || seal( payload || pad )
//
// where m1/m2 are the next 4 bytes of SHAKE128(salt || key); the AEAD nonce
// starts as the salt and is bumped (little endian) after each Seal/Open.

import (
	"bytes"
	"crypto/aes"
	"os"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"
)

const passSaltLen = 12

var passConst = []byte{
	0xd8, 0xb8, 0xc0, 0x66, 0xc1, 0x0e, 0x8b, 0x0d,
	0x1b, 0x1b, 0xa3, 0xad, 0x1f, 0x7d, 0xe1, 0x52,
	0x56, 0x25, 0xd0, 0x3f, 0x9d, 0x9f, 0x68, 0x2f,
	0x1b, 0xd6, 0x09, 0x7b, 0x13, 0xa2, 0x2b, 0x38,
}

// PassConfig holds the derived material of one subscription.
type PassConfig struct {
	Method   Method
	Password string
	Padding  PaddingConfig

	psk   []byte
	token [16]byte
}

// NewPassConfig derives psk and token from the passphrase.
func NewPassConfig(method Method, password string) (*PassConfig, error) {
	keyLen := method.KeyLen()
	if keyLen == 0 {
		return nil, fmt.Errorf("ninja: unsupported pass method %q", string(method))
	}
	if password == "" {
		return nil, fmt.Errorf("ninja: empty pass password")
	}
	cfg := &PassConfig{Method: method, Password: password}
	h := sha3.New512()
	h.Write([]byte(password))
	cfg.psk = h.Sum(nil)[:keyLen]
	tok, err := hkdf.Key(sha3.New512, cfg.psk, passConst, password, 16)
	if err != nil {
		return nil, err
	}
	copy(cfg.token[:], tok)
	return cfg, nil
}

// Token is the 16 byte authentication token carried by the first client record.
func (c *PassConfig) Token() []byte { return c.token[:] }

func (c *PassConfig) newAEAD(salt []byte) (cipher.AEAD, []byte, error) {
	key, err := hkdf.Key(sha3.New512, c.psk, salt, string(passConst), c.Method.KeyLen())
	if err != nil {
		return nil, nil, err
	}
	if c.Method == MethodChacha20Poly1305 {
		a, err := chacha20poly1305.New(key)
		return a, key, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	a, err := cipher.NewGCM(block)
	return a, key, err
}

func incPassNonce(n []byte) {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

// PassConn is the authenticated, encrypted record stream.
type PassConn struct {
	net.Conn
	cfg *PassConfig

	prefix []byte // first-record prefix (token [|| 0x03 0x01 socksAddr])
	sent   bool

	wmu sync.Mutex
	rmu sync.Mutex

	encReady bool
	encAEAD  cipher.AEAD
	encSalt  []byte
	encNonce []byte
	encShake sha3.ShakeHash

	decReady bool
	decAEAD  cipher.AEAD
	decNonce []byte
	decShake sha3.ShakeHash

	rbuf []byte

	// server side: strip the peer's first record prefix (token + marker [+ addr])
	server   bool
	stripped bool
}

// NewPassConn wraps raw. socksAddr, when not nil, is announced in the first
// record; a plain client leaves it nil and lets the core carry the address.
func NewPassConn(raw net.Conn, cfg *PassConfig, socksAddr []byte) *PassConn {
	c := &PassConn{Conn: raw, cfg: cfg}
	if socksAddr == nil {
		c.prefix = []byte{0x01}
	} else {
		c.prefix = append([]byte{0x03, 0x01}, socksAddr...)
	}
	return c
}

// NewPassServerConn wraps a server side transport. The peer (client) prefixes its
// first record with token(16)||0x01 (or token||0x03||socksAddr); the server strips
// it before handing the core stream upwards.
func NewPassServerConn(raw net.Conn, cfg *PassConfig) *PassConn {
	return &PassConn{Conn: raw, cfg: cfg, server: true}
}

func (c *PassConn) initEnc() error {
	if c.encReady {
		return nil
	}
	salt := make([]byte, passSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	aead, key, err := c.cfg.newAEAD(salt)
	if err != nil {
		return err
	}
	c.encAEAD = aead
	c.encSalt = salt
	c.encNonce = append([]byte{}, salt...)
	sh := sha3.NewShake128()
	sh.Write(salt)
	sh.Write(key)
	c.encShake = sh
	c.encReady = true
	return nil
}

func (c *PassConn) initDec() error {
	if c.decReady {
		return nil
	}
	salt := make([]byte, passSaltLen)
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return err
	}
	aead, key, err := c.cfg.newAEAD(salt)
	if err != nil {
		return err
	}
	c.decAEAD = aead
	c.decNonce = append([]byte{}, salt...)
	sh := sha3.NewShake128()
	sh.Write(salt)
	sh.Write(key)
	c.decShake = sh
	c.decReady = true
	return nil
}

// Write seals b, adding the token prefix and the salt on the very first record.
func (c *PassConn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := c.initEnc(); err != nil {
		return 0, err
	}
	payload := b
	first := !c.sent
	c.sent = true
	if first && !c.server {
		buf := make([]byte, 0, len(c.cfg.token)+len(c.prefix)+len(b))
		buf = append(buf, c.cfg.token[:]...)
		buf = append(buf, c.prefix...)
		buf = append(buf, b...)
		payload = buf
	}
	if len(payload) > 0xffff {
		return 0, fmt.Errorf("ninja: pass record too large (%d)", len(payload))
	}
	pad := c.cfg.Padding.PaddingLen(len(payload))
	if os.Getenv("NINJA_DEBUG") != "" {
		println("[ninja] pass write payload", len(payload), "pad", pad, "first", first, "nonce0", int(c.encNonce[0]), "server", c.server)
	}
	if pad < 0 {
		pad = 0
	}
	if pad > 0xffff-len(payload) {
		pad = 0xffff - len(payload)
	}

	mask := make([]byte, 4)
	c.encShake.Read(mask)
	var hdr [4]byte
	binary.BigEndian.PutUint16(hdr[0:2], uint16(len(payload))^binary.BigEndian.Uint16(mask[0:2]))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(pad)^binary.BigEndian.Uint16(mask[2:4]))

	body := make([]byte, len(payload)+pad)
	copy(body, payload)
	if pad > 0 {
		if _, err := rand.Read(body[len(payload):]); err != nil {
			return 0, err
		}
	}

	sealedHdr := c.encAEAD.Seal(nil, c.encNonce, hdr[:], nil)
	incPassNonce(c.encNonce)
	sealedBody := c.encAEAD.Seal(nil, c.encNonce, body, nil)
	incPassNonce(c.encNonce)

	out := make([]byte, 0, passSaltLen+len(sealedHdr)+len(sealedBody))
	if first {
		out = append(out, c.encSalt...)
	}
	out = append(out, sealedHdr...)
	out = append(out, sealedBody...)
	if _, err := c.Conn.Write(out); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *PassConn) readRecord() error {
	if err := c.initDec(); err != nil {
		return err
	}
	hdrCt := make([]byte, 4+c.decAEAD.Overhead())
	if _, err := io.ReadFull(c.Conn, hdrCt); err != nil {
		return err
	}
	if os.Getenv("NINJA_DEBUG") != "" {
		println("[ninja] pass read hdr try nonce0", int(c.decNonce[0]), "nonce1", int(c.decNonce[1]), "server", c.server)
	}
	hdr, err := c.decAEAD.Open(nil, c.decNonce, hdrCt, nil)
	if err != nil {
		return fmt.Errorf("ninja: pass header: %w", err)
	}
	incPassNonce(c.decNonce)

	mask := make([]byte, 4)
	c.decShake.Read(mask)
	ln := int(binary.BigEndian.Uint16(hdr[0:2]) ^ binary.BigEndian.Uint16(mask[0:2]))
	pad := int(binary.BigEndian.Uint16(hdr[2:4]) ^ binary.BigEndian.Uint16(mask[2:4]))
	if ln < 0 || pad < 0 || ln+pad > 0xffff {
		return fmt.Errorf("ninja: pass bad length len=%d pad=%d", ln, pad)
	}
	bodyCt := make([]byte, ln+pad+c.decAEAD.Overhead())
	if _, err := io.ReadFull(c.Conn, bodyCt); err != nil {
		return err
	}
	body, err := c.decAEAD.Open(nil, c.decNonce, bodyCt, nil)
	if err != nil {
		return fmt.Errorf("ninja: pass body: %w", err)
	}
	incPassNonce(c.decNonce)
	if os.Getenv("NINJA_DEBUG") != "" {
		println("[ninja] pass read ln", ln, "pad", pad, "server", c.server, "nonce0", int(c.decNonce[0]))
	}
	c.rbuf = body[:ln]
	if c.server && !c.stripped {
		c.stripped = true
		payload := c.rbuf
		if len(payload) < 17 {
			return fmt.Errorf("ninja: short first payload %d", len(payload))
		}
		if !bytes.Equal(payload[:16], c.cfg.token[:]) {
			// still surface the stream; upper layer reports the mismatch
		}
		marker := payload[16]
		cut := 17
		switch marker {
		case 0x01:
		case 0x03:
			if len(payload) < 18 {
				return fmt.Errorf("ninja: short socks first payload")
			}
			// payload[16]=0x03, payload[17]=0x01 and the socks address (which
			// starts with its own ATYP byte) follows right after.
			alen := socksAddrLen(payload[18:])
			cut = 18 + alen
		default:
			return fmt.Errorf("ninja: unknown pass marker %#x", marker)
		}
		if len(payload) < cut {
			return fmt.Errorf("ninja: first payload %d < prefix %d", len(payload), cut)
		}
		c.rbuf = payload[cut:]
	}
	return nil
}

// socksAddrLen returns the encoded length of a socks5 address.
func socksAddrLen(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	switch b[0] {
	case 0x01:
		return 1 + 4 + 2
	case 0x03:
		if len(b) < 2 {
			return 0
		}
		return 1 + 1 + int(b[1]) + 2
	case 0x04:
		return 1 + 16 + 2
	}
	return 0
}

// Read returns payload bytes of the decrypted records.
func (c *PassConn) Read(b []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.rbuf) == 0 {
		if err := c.readRecord(); err != nil {
			return 0, err
		}
	}
	n := copy(b, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}
