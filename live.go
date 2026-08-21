package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// --- TZSP -----------------------------------------------------------------
//
// TZSP (TaZmen Sniffer Protocol) is what MikroTik's `/tool sniffer` streams and
// what ntopng/Wireshark ingest. Layout:
//
//	byte 0    version (1)
//	byte 1    type
//	byte 2-3  encapsulated protocol (big-endian; 1 = Ethernet)
//	then      tagged fields until END tag (0x01); PADDING = 0x00
//	then      the original captured frame
//
// tzspPayload returns the encapsulated frame and its link protocol.
func tzspPayload(buf []byte) (proto uint16, frame []byte, ok bool) {
	if len(buf) < 4 || buf[0] != 0x01 {
		return 0, nil, false
	}
	proto = uint16(buf[2])<<8 | uint16(buf[3])
	i := 4
	for i < len(buf) {
		tag := buf[i]
		switch tag {
		case 0x01: // TAG_END
			return proto, buf[i+1:], true
		case 0x00: // TAG_PADDING
			i++
		default:
			if i+1 >= len(buf) {
				return 0, nil, false
			}
			length := int(buf[i+1])
			i += 2 + length
		}
	}
	return 0, nil, false
}

func tzspDecoder(proto uint16) gopacket.Decoder {
	switch proto {
	case 0x01: // Ethernet
		return layers.LayerTypeEthernet
	default:
		return layers.LayerTypeEthernet
	}
}

// --- live flow tracking ---------------------------------------------------

const (
	liveMaxFlowBytes = 64 * 1024 // creds appear early; cap memory per flow
	liveIdleEvict    = 120 * time.Second
)

type liveFlow struct {
	buf      bytes.Buffer
	portA    int
	portB    int
	ipA      string
	ipB      string
	label    string
	lastSeen time.Time
}

type LiveManager struct {
	mu      sync.Mutex
	flows   map[flowKey]*liveFlow
	sources map[string]time.Time
	packets uint64
	lastPkt time.Time
	port    int
	bind    string
	store   *Store

	listMu     sync.RWMutex
	allowed    []*net.IPNet
	blocked    []*net.IPNet
	blockedStr []string
	staticCSV  string // BLOCKED_SOURCES from env, always applied
}

type SourceInfo struct {
	IP       string
	LastSeen time.Time
	Blocked  bool
}

type LiveStatus struct {
	Enabled     bool
	Port        int
	Packets     uint64
	ActiveFlows int
	Sources     int
	LastPacket  time.Time
	HasLast     bool
	AllowlistOn bool
	Devices     []SourceInfo
	Blocked     []string
}

func parseAllowed(csv string) []*net.IPNet {
	var nets []*net.IPNet
	for _, part := range strings.Split(csv, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		if !strings.Contains(p, "/") {
			if strings.Contains(p, ":") {
				p += "/128"
			} else {
				p += "/32"
			}
		}
		if _, n, err := net.ParseCIDR(p); err == nil {
			nets = append(nets, n)
		} else {
			log.Printf("live: ignoring invalid ALLOWED_SOURCES entry %q", part)
		}
	}
	return nets
}

func NewLiveManager(store *Store, bind string, port int, allowedCSV, blockedCSV string) *LiveManager {
	m := &LiveManager{
		flows:     map[flowKey]*liveFlow{},
		sources:   map[string]time.Time{},
		port:      port,
		bind:      bind,
		allowed:   parseAllowed(allowedCSV),
		store:     store,
		staticCSV: blockedCSV,
	}
	m.RebuildBlocked()
	return m
}

// RebuildBlocked recomputes the blocklist from the static env value plus the
// dynamic entries persisted in the store. Call after any block/unblock change.
func (m *LiveManager) RebuildBlocked() {
	entries := append([]string{}, splitCSV(m.staticCSV)...)
	if m.store != nil {
		entries = append(entries, m.store.BlockedList()...)
	}
	var nets []*net.IPNet
	var strs []string
	seen := map[string]bool{}
	for _, e := range entries {
		norm, ok := normalizeCIDR(e)
		if !ok || seen[norm] {
			continue
		}
		seen[norm] = true
		if _, n, err := net.ParseCIDR(norm); err == nil {
			nets = append(nets, n)
			strs = append(strs, norm)
		}
	}
	m.listMu.Lock()
	m.blocked = nets
	m.blockedStr = strs
	m.listMu.Unlock()
}

func splitCSV(csv string) []string {
	var out []string
	for _, p := range strings.Split(csv, ",") {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// sourceAllowed returns false if the source is blocked, otherwise honors the
// allowlist (empty allowlist = accept all, which is the LAN default).
func (m *LiveManager) sourceAllowed(ip net.IP) bool {
	m.listMu.RLock()
	defer m.listMu.RUnlock()
	for _, n := range m.blocked {
		if n.Contains(ip) {
			return false
		}
	}
	if len(m.allowed) == 0 {
		return true
	}
	for _, n := range m.allowed {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (m *LiveManager) isBlocked(ip net.IP) bool {
	m.listMu.RLock()
	defer m.listMu.RUnlock()
	for _, n := range m.blocked {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Start binds the UDP socket and processes datagrams until the process exits.
func (m *LiveManager) Start() error {
	addr := &net.UDPAddr{IP: net.ParseIP(m.bind), Port: m.port}
	if addr.IP == nil {
		addr.IP = net.IPv4zero
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	if len(m.allowed) > 0 {
		log.Printf("live: listening on %s:%d (TZSP), allowlist=%d source(s)", m.bind, m.port, len(m.allowed))
	} else {
		log.Printf("live: listening on %s:%d (TZSP), accept-all (LAN mode); use the blocklist to drop sources", m.bind, m.port)
	}

	go m.janitor()

	buf := make([]byte, 65535)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("live: read error: %v", err)
			continue
		}
		if !m.sourceAllowed(src.IP) {
			continue // dropped: blocked or not in allowlist
		}
		datagram := make([]byte, n)
		copy(datagram, buf[:n])
		m.handleDatagram(src.IP.String(), datagram)
	}
}

func (m *LiveManager) handleDatagram(srcIP string, data []byte) {
	proto, frame, ok := tzspPayload(data)
	if !ok || len(frame) == 0 {
		return
	}
	packet := gopacket.NewPacket(frame, tzspDecoder(proto).(gopacket.LayerType), gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	ipA, ipB, portA, portB, payload, ok := tcpTuple(packet)
	if !ok {
		return
	}

	epA := fmt.Sprintf("%s:%d", ipA, portA)
	epB := fmt.Sprintf("%s:%d", ipB, portB)
	var key flowKey
	var label string
	if epA <= epB {
		key, label = flowKey{epA, epB}, epA+" <-> "+epB
	} else {
		key, label = flowKey{epB, epA}, epB+" <-> "+epA
	}

	m.mu.Lock()
	m.packets++
	m.lastPkt = time.Now()
	m.sources[srcIP] = m.lastPkt

	f := m.flows[key]
	if f == nil {
		f = &liveFlow{portA: portA, portB: portB, ipA: ipA, ipB: ipB, label: label}
		m.flows[key] = f
	}
	if f.buf.Len() < liveMaxFlowBytes {
		f.buf.Write(payload)
	}
	f.lastSeen = m.lastPkt
	proto2 := guessProto(f.portA, f.portB)
	text := f.buf.String()
	m.mu.Unlock()

	if proto2 == "" {
		return
	}
	// Re-run extraction on the flow buffer. The store dedups by user+pass, so
	// repeatedly finding the same credential as the buffer grows is harmless.
	// In the live path we skip half-captured pairs (USER seen but PASS not yet)
	// so a placeholder "?" record never lands in the list.
	var creds []Credential
	for _, pr := range extractByProto(proto2, text) {
		if pr.user == "?" || pr.pass == "?" || pr.user == "" || pr.pass == "" {
			continue
		}
		creds = append(creds, Credential{
			Protocol: proto2,
			Flow:     label,
			Username: pr.user,
			Password: pr.pass,
			IPs:      uniqueIPs(ipA, ipB),
		})
	}
	if len(creds) > 0 {
		m.store.Merge(creds)
	}
}

func (m *LiveManager) janitor() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		m.mu.Lock()
		for k, f := range m.flows {
			if now.Sub(f.lastSeen) > liveIdleEvict {
				delete(m.flows, k)
			}
		}
		for ip, seen := range m.sources {
			if now.Sub(seen) > 10*time.Minute {
				delete(m.sources, ip)
			}
		}
		m.mu.Unlock()
	}
}

func (m *LiveManager) Status() LiveStatus {
	if m == nil {
		return LiveStatus{Enabled: false}
	}
	m.mu.Lock()
	devices := make([]SourceInfo, 0, len(m.sources))
	for ip, seen := range m.sources {
		devices = append(devices, SourceInfo{IP: ip, LastSeen: seen, Blocked: m.isBlocked(net.ParseIP(ip))})
	}
	st := LiveStatus{
		Enabled:     true,
		Port:        m.port,
		Packets:     m.packets,
		ActiveFlows: len(m.flows),
		Sources:     len(m.sources),
		LastPacket:  m.lastPkt,
		HasLast:     !m.lastPkt.IsZero(),
		Devices:     devices,
	}
	m.mu.Unlock()

	sort.SliceStable(devices, func(i, j int) bool { return devices[i].LastSeen.After(devices[j].LastSeen) })

	m.listMu.RLock()
	st.AllowlistOn = len(m.allowed) > 0
	st.Blocked = append([]string{}, m.blockedStr...)
	m.listMu.RUnlock()
	return st
}
