package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/contextutils"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/iwan"

	"golang.org/x/sync/semaphore"
)

const defaultIwanIdleTimeout = 60 * time.Second

// Iwan is a Panabit iWAN SD-WAN L3 outbound adapter backed by mihomo's
// userspace IP stack (mipstack / gVisor), requiring no OS TUN privileges.
type Iwan struct {
	*Base
	option *IwanOption
	config iwan.ClientConfig

	tunDevice ipStack
	client    *iwan.Client
	resolver  resolver.Resolver
	dns       []dns.NameServer

	idle *idleCloser

	runCtx        context.Context
	runCancel     context.CancelFunc
	sessionCancel context.CancelFunc
	runLock       *semaphore.Weighted
	running       bool
}

type IwanOption struct {
	BasicOption
	Name             string        `proxy:"name"`
	Server           string        `proxy:"server"`
	Port             int           `proxy:"port"`
	Username         string        `proxy:"username"`
	Password         string        `proxy:"password"`
	MTU              int           `proxy:"mtu,omitempty"`
	Encrypt          bool          `proxy:"encrypt,omitempty"`
	UDP              bool          `proxy:"udp,omitempty"`
	HandshakeTimeout int           `proxy:"handshake-timeout,omitempty"`
	IdleTimeout      *int          `proxy:"idle-timeout,omitempty"`
	PipeID           int           `proxy:"pipe-id,omitempty"`
	PipeIdx          int           `proxy:"pipe-idx,omitempty"`
	IPStack          IPStackOption `proxy:"ip-stack,omitempty"`
	RemoteDnsResolve bool          `proxy:"remote-dns-resolve,omitempty"`
	Dns              []string      `proxy:"dns,omitempty"`
}

func NewIwan(option IwanOption) (*Iwan, error) {
	if option.Server == "" {
		return nil, errors.New("iwan: server is required")
	}
	if option.Port <= 0 || option.Port > 65535 {
		return nil, fmt.Errorf("iwan: invalid port %d", option.Port)
	}
	if option.Username == "" {
		return nil, errors.New("iwan: username is required")
	}
	if option.Password == "" {
		return nil, errors.New("iwan: password is required")
	}
	if len(option.Password) > 16 {
		log.Warnln("[iWAN](%s) password longer than 16 bytes will be truncated by the protocol AES-128 block", option.Name)
	}

	mtu := option.MTU
	if mtu == 0 {
		mtu = iwan.DefaultMTU
	}
	if mtu < iwan.MinMTU || mtu > iwan.MaxMTU {
		return nil, fmt.Errorf("iwan: mtu %d out of range [%d, %d]", mtu, iwan.MinMTU, iwan.MaxMTU)
	}
	if option.HandshakeTimeout < 0 {
		return nil, errors.New("iwan: handshake-timeout must be non-negative")
	}
	if option.PipeID < 0 || option.PipeID > 0x7fff {
		return nil, fmt.Errorf("iwan: invalid pipe-id %d", option.PipeID)
	}
	if option.PipeIdx < 0 || option.PipeIdx > 1 {
		return nil, fmt.Errorf("iwan: invalid pipe-idx %d", option.PipeIdx)
	}

	idleTimeout := defaultIwanIdleTimeout
	if option.IdleTimeout != nil {
		if *option.IdleTimeout < 0 {
			return nil, errors.New("iwan: idle-timeout must be non-negative")
		}
		idleTimeout = time.Duration(*option.IdleTimeout) * time.Second
	}

	option.IPStack.normalize()
	if err := option.IPStack.validate(); err != nil {
		return nil, err
	}

	var parsedDNS []dns.NameServer
	if option.RemoteDnsResolve && len(option.Dns) > 0 {
		nss, err := dns.ParseNameServer(option.Dns)
		if err != nil {
			return nil, fmt.Errorf("iwan: parse dns: %w", err)
		}
		parsedDNS = nss
	}

	handshakeTimeout := iwan.DefaultHandshakeTimeout
	if option.HandshakeTimeout > 0 {
		handshakeTimeout = time.Duration(option.HandshakeTimeout) * time.Second
	}

	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	runCtx, runCancel := context.WithCancel(context.Background())

	outbound := &Iwan{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Iwan,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
		config: iwan.ClientConfig{
			Username:         option.Username,
			Password:         option.Password,
			MTU:              uint16(mtu),
			Encrypt:          option.Encrypt,
			PipeID:           uint16(option.PipeID),
			PipeIdx:          uint16(option.PipeIdx),
			HandshakeTimeout: handshakeTimeout,
			EchoInterval:     iwan.DefaultEchoInterval,
			DataTimeout:      iwan.DefaultDataTimeout,
		},
		dns:       parsedDNS,
		runCtx:    runCtx,
		runCancel: runCancel,
		runLock:   semaphore.NewWeighted(1),
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	outbound.idle = newIdleCloser(idleTimeout, outbound.closeSession)
	return outbound, nil
}

// DialContext implements C.ProxyAdapter.
func (i *Iwan) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	i.idle.acquire()
	tunDevice, r, err := i.run(ctx)
	if err != nil {
		i.idle.release()
		return nil, err
	}

	var conn net.Conn
	if !metadata.Resolved() || r != nil {
		if r == nil {
			r = resolver.DefaultResolver
		}
		options := i.DialOptions()
		// iWAN is an IPv4-only L3 tunnel.
		options = append(options, dialer.WithOnlySingleStack(true))
		options = append(options, dialer.WithResolver(r))
		options = append(options, dialer.WithNetDialer(ipStackNetDialer{stack: tunDevice}))
		conn, err = dialer.NewDialer(options...).DialContext(ctx, "tcp", metadata.RemoteAddress())
	} else {
		if !metadata.DstIP.Unmap().Is4() {
			i.idle.release()
			return nil, errors.New("iwan: IPv6 destinations are not supported")
		}
		conn, err = tunDevice.DialTCP(ctx, "tcp", netip.AddrPort{}, metadata.AddrPort())
	}
	if err != nil {
		i.idle.release()
		return nil, err
	}
	if conn == nil {
		i.idle.release()
		return nil, errors.New("iwan: conn is nil")
	}
	return NewConn(i.idle.trackConn(conn), i), nil
}

// ListenPacketContext implements C.ProxyAdapter.
func (i *Iwan) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	i.idle.acquire()
	tunDevice, r, err := i.run(ctx)
	if err != nil {
		i.idle.release()
		return nil, err
	}
	if err = i.resolveUDP(ctx, metadata, r); err != nil {
		i.idle.release()
		return nil, err
	}
	if metadata.DstIP.IsValid() && !metadata.DstIP.Unmap().Is4() {
		i.idle.release()
		return nil, errors.New("iwan: IPv6 destinations are not supported")
	}
	pc, err := tunDevice.ListenUDP(ctx, "udp", netip.AddrPort{})
	if err != nil {
		i.idle.release()
		return nil, err
	}
	if pc == nil {
		i.idle.release()
		return nil, errors.New("iwan: packetConn is nil")
	}
	return NewPacketConn(i.idle.trackPacketConn(pc), i), nil
}

// ResolveUDP implements C.ProxyAdapter.
func (i *Iwan) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	i.idle.acquire()
	defer i.idle.release()
	_, r, err := i.run(ctx)
	if err != nil {
		return err
	}
	return i.resolveUDP(ctx, metadata, r)
}

func (i *Iwan) resolveUDP(ctx context.Context, metadata *C.Metadata, r resolver.Resolver) error {
	if (!metadata.Resolved() || r != nil) && metadata.Host != "" {
		if r == nil {
			r = resolver.DefaultResolver
		}
		ip, err := resolveIPWithResolver(ctx, metadata.Host, C.IPv4Only, r)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
}

// ProxyInfo implements C.ProxyAdapter.
func (i *Iwan) ProxyInfo() C.ProxyInfo {
	info := i.Base.ProxyInfo()
	info.DialerProxy = i.option.DialerProxy
	return info
}

// IsL3Protocol implements C.ProxyAdapter.
func (i *Iwan) IsL3Protocol(metadata *C.Metadata) bool {
	return true
}

// closeSession tears down the current active tunnel session without canceling
// runCtx, allowing future dials to transparently reconnect.
func (i *Iwan) closeSession() {
	_ = i.runLock.Acquire(context.Background(), 1)
	cancel := i.sessionCancel
	client := i.client
	tunDevice := i.tunDevice
	i.sessionCancel = nil
	i.client = nil
	i.tunDevice = nil
	if len(i.dns) == 0 {
		i.resolver = nil
	}
	i.running = false
	i.runLock.Release(1)

	if cancel != nil {
		cancel()
	}
	if client != nil {
		_ = client.Close()
	}
	if tunDevice != nil {
		_ = tunDevice.Close()
	}
}

// Close implements C.ProxyAdapter.
func (i *Iwan) Close() error {
	if i.runCancel != nil {
		i.runCancel()
	}
	i.closeSession()
	return nil
}

func (i *Iwan) run(ctx context.Context) (ipStack, resolver.Resolver, error) {
	runCtx, cancel := context.WithCancel(ctx)
	stop := contextutils.AfterFunc(i.runCtx, cancel)
	defer func() {
		stop()
		cancel()
	}()

	if err := i.runLock.Acquire(runCtx, 1); err != nil {
		return nil, nil, err
	}
	releaseRunLock := true
	defer func() {
		if releaseRunLock {
			i.runLock.Release(1)
		}
	}()

	if i.running {
		if i.tunDevice == nil {
			return nil, nil, net.ErrClosed
		}
		return i.tunDevice, i.resolver, nil
	}
	if i.runCtx.Err() != nil {
		return nil, nil, i.runCtx.Err()
	}

	type runResult struct {
		tunDevice ipStack
		resolver  resolver.Resolver
		err       error
	}

	releaseRunLock = false
	resultCh := make(chan runResult, 1)
	go func() {
		defer i.runLock.Release(1)

		hsCtx, hsCancel := context.WithTimeout(i.runCtx, i.config.HandshakeTimeout)
		defer hsCancel()

		tunDevice, r, err := i.startLocked(hsCtx)
		resultCh <- runResult{tunDevice: tunDevice, resolver: r, err: err}
	}()

	select {
	case result := <-resultCh:
		return result.tunDevice, result.resolver, result.err
	case <-runCtx.Done():
		return nil, nil, runCtx.Err()
	}
}

func (i *Iwan) startLocked(handshakeCtx context.Context) (ipStack, resolver.Resolver, error) {
	udpConn, err := i.dialer.DialContext(handshakeCtx, "udp", i.addr)
	if err != nil {
		return nil, nil, fmt.Errorf("connect iWAN server %s: %w", i.addr, err)
	}

	client, err := iwan.NewClient(i.config, udpConn)
	if err != nil {
		_ = udpConn.Close()
		return nil, nil, err
	}

	ack, err := client.Handshake(handshakeCtx)
	if err != nil {
		_ = client.Close()
		return nil, nil, fmt.Errorf("iWAN handshake with %s: %w", i.addr, err)
	}
	log.Debugln("[iWAN](%s) handshake complete: ip=%s mtu=%d encrypt=%t dns=%v", i.name, ack.PeerIP, ack.MTU, ack.Encrypt, ack.DNS)

	// Point-to-point /32 prefix ensures all peer and subnet IPv4 traffic traverses the tunnel.
	prefixes := []netip.Prefix{netip.PrefixFrom(ack.PeerIP, 32)}
	tunDevice, err := newIPStack(i.option.IPStack, prefixes, uint32(ack.MTU))
	if err != nil {
		_ = client.Close()
		return nil, nil, fmt.Errorf("create iWAN stack device: %w", err)
	}
	if err := tunDevice.Start(); err != nil {
		_ = client.Close()
		_ = tunDevice.Close()
		return nil, nil, err
	}

	i.client = client
	i.tunDevice = tunDevice
	i.running = true

	if i.option.RemoteDnsResolve && i.resolver == nil {
		nss := append([]dns.NameServer(nil), i.dns...)
		if len(nss) == 0 && len(ack.DNS) > 0 {
			var rawDNS []string
			for _, ip := range ack.DNS {
				rawDNS = append(rawDNS, ip.String())
			}
			if parsed, parseErr := dns.ParseNameServer(rawDNS); parseErr == nil {
				nss = parsed
			}
		}
		if len(nss) > 0 {
			for idx := range nss {
				nss[idx].ProxyAdapter = i
			}
			i.resolver = dns.NewResolver(dns.Config{
				Main: nss,
				IPv6: false,
			})
		}
	}

	i.startPacketLoops()
	return i.tunDevice, i.resolver, nil
}

func (i *Iwan) startPacketLoops() {
	sessCtx, sessCancel := context.WithCancel(i.runCtx)
	i.sessionCancel = sessCancel
	client := i.client
	tunDevice := i.tunDevice

	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			sessCancel()
			_ = client.Close()
			_ = tunDevice.Close()
			_ = i.runLock.Acquire(context.Background(), 1)
			if i.client == client {
				i.sessionCancel = nil
				i.client = nil
				i.tunDevice = nil
				i.running = false
			}
			i.runLock.Release(1)
		})
	}

	// Outbound loop: userspace ipStack -> iWAN UDP tunnel.
	go func() {
		defer stop()
		buf := make([]byte, 64*1024)
		bufs := [][]byte{buf}
		sizes := []int{0}
		for sessCtx.Err() == nil {
			_, err := tunDevice.Read(bufs, sizes, 0)
			if err != nil {
				if sessCtx.Err() == nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
					log.Errorln("[iWAN](%s) error reading from stack device: %v", i.name, err)
				}
				return
			}
			if sizes[0] <= 0 {
				continue
			}
			if err := client.WriteIPPacket(buf[:sizes[0]]); err != nil {
				if sessCtx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
					log.Warnln("[iWAN](%s) error writing packet: %v", i.name, err)
				}
				return
			}
		}
	}()

	// Inbound loop: iWAN UDP tunnel -> userspace ipStack.
	go func() {
		defer stop()
		for sessCtx.Err() == nil {
			packet, err := client.ReadIPPacket(sessCtx)
			if err != nil {
				if sessCtx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
					log.Warnln("[iWAN](%s) link closed while reading packet: %v", i.name, err)
				}
				return
			}
			if _, err := tunDevice.Write([][]byte{packet}, 0); err != nil {
				if sessCtx.Err() == nil && !errors.Is(err, net.ErrClosed) {
					log.Errorln("[iWAN](%s) error writing to stack device: %v", i.name, err)
				}
				return
			}
		}
	}()

	// Keepalive & data-timeout loop (matches iwand.c: ECHO every 2s, timeout 15s).
	go func() {
		defer stop()
		ticker := time.NewTicker(i.config.EchoInterval)
		defer ticker.Stop()
		for {
			select {
			case <-sessCtx.Done():
				return
			case <-ticker.C:
				if since := client.SinceReceive(); since > i.config.DataTimeout {
					log.Warnln("[iWAN](%s) data timeout: no packet received for %s", i.name, since.Round(time.Second))
					return
				}
				if err := client.WriteEcho(); err != nil {
					if sessCtx.Err() == nil && !errors.Is(err, net.ErrClosed) {
						log.Warnln("[iWAN](%s) error sending ECHO: %v", i.name, err)
					}
					return
				}
			}
		}
	}()
}

var _ C.ProxyAdapter = (*Iwan)(nil)
