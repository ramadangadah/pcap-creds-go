package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// Credential is a single recovered cleartext login.
type Credential struct {
	Protocol string
	Flow     string
	Username string
	Password string
	IPs      []string // the two endpoint IPs involved in the flow
}

type flowKey struct {
	a, b string // "ip:port" endpoints, sorted so both directions collapse to one key
}

type flowData struct {
	buf   bytes.Buffer
	portA int
	portB int
	ipA   string
	ipB   string
	label string
}

var protoPorts = map[string][]int{
	"ftp":    {21},
	"pop3":   {110, 995},
	"imap":   {143, 993},
	"http":   {80, 8080},
	"smtp":   {25, 587},
	"telnet": {23},
}

func guessProto(pa, pb int) string {
	for proto, ports := range protoPorts {
		for _, p := range ports {
			if pa == p || pb == p {
				return proto
			}
		}
	}
	return ""
}

// firstDecoder maps a capture's link type to the gopacket decoder to start
// from. gopacket knows Ethernet (the common case for interface captures), but
// captures made from the IP layer up — e.g. scapy building from IP(), or a
// router sniffing in "IP only" mode — use raw-IP link types it won't decode
// automatically. We handle those explicitly so both kinds of file just work.
func firstDecoder(lt layers.LinkType) gopacket.Decoder {
	switch lt {
	case layers.LinkTypeEthernet:
		return layers.LayerTypeEthernet
	case layers.LinkTypeRaw, layers.LinkType(12) /* raw */, layers.LinkType(228) /* IPv4 */ :
		return layers.LayerTypeIPv4
	case layers.LinkType(229): // IPv6
		return layers.LayerTypeIPv6
	case layers.LinkTypeLinuxSLL:
		return layers.LayerTypeLinuxSLL
	case layers.LinkTypeNull, layers.LinkTypeLoop:
		return layers.LayerTypeLoopback
	default:
		// Fall back to Ethernet for genuinely unknown types; most real
		// interface captures are Ethernet.
		return layers.LayerTypeEthernet
	}
}

// newPacketSource sniffs the file magic to pick the right reader, so a single
// upload endpoint transparently handles both .pcap and .pcapng.
func newPacketSource(data []byte) (*gopacket.PacketSource, error) {
	r := bytes.NewReader(data)
	// pcapng Section Header Block starts with 0x0A0D0D0A
	if len(data) >= 4 && data[0] == 0x0A && data[1] == 0x0D && data[2] == 0x0D && data[3] == 0x0A {
		ng, err := pcapgo.NewNgReader(r, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return nil, err
		}
		return gopacket.NewPacketSource(ng, firstDecoder(ng.LinkType())), nil
	}
	pr, err := pcapgo.NewReader(r)
	if err != nil {
		return nil, err
	}
	return gopacket.NewPacketSource(pr, firstDecoder(pr.LinkType())), nil
}

// loadStreams reassembles raw TCP payload bytes per bidirectional flow,
// preserving packet order (PacketSource yields packets in file order).
func loadStreams(data []byte) (map[flowKey]*flowData, error) {
	src, err := newPacketSource(data)
	if err != nil {
		return nil, err
	}
	src.DecodeOptions = gopacket.DecodeOptions{Lazy: true, NoCopy: true}

	flows := make(map[flowKey]*flowData)

	for packet := range src.Packets() {
		net := packet.NetworkLayer()
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if net == nil || tcpLayer == nil {
			continue
		}
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok || len(tcp.Payload) == 0 {
			continue
		}

		srcIP, dstIP := net.NetworkFlow().Endpoints()
		portA := int(tcp.SrcPort)
		portB := int(tcp.DstPort)
		epA := fmt.Sprintf("%s:%d", srcIP.String(), portA)
		epB := fmt.Sprintf("%s:%d", dstIP.String(), portB)

		var key flowKey
		var label string
		if epA <= epB {
			key = flowKey{epA, epB}
			label = epA + " <-> " + epB
		} else {
			key = flowKey{epB, epA}
			label = epB + " <-> " + epA
		}

		fd := flows[key]
		if fd == nil {
			fd = &flowData{
				portA: portA, portB: portB,
				ipA: srcIP.String(), ipB: dstIP.String(),
				label: label,
			}
			flows[key] = fd
		}
		fd.buf.Write(tcp.Payload)
	}
	return flows, nil
}

var (
	reUser      = regexp.MustCompile(`(?i)USER\s+(\S+)\r?\n`)
	rePass      = regexp.MustCompile(`(?i)PASS\s+(\S+)\r?\n`)
	reImap      = regexp.MustCompile(`(?im)^\S+\s+LOGIN\s+"?([^"\s]+)"?\s+"?([^"\r\n]+?)"?\s*$`)
	reBasic     = regexp.MustCompile(`(?i)Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)`)
	reAuthPlain = regexp.MustCompile(`(?i)AUTH PLAIN\s+([A-Za-z0-9+/=]+)`)
	reAuthLogin = regexp.MustCompile(`(?i)AUTH LOGIN\r?\n([A-Za-z0-9+/=]+)\r?\n([A-Za-z0-9+/=]+)`)
	reTelnet    = regexp.MustCompile(`(?is)login:\s*([^\r\n]+)\r?\n.*?password:\s*([^\r\n]+)`)
)

func b64decode(s string) ([]byte, bool) {
	if d, err := base64.StdEncoding.DecodeString(s); err == nil {
		return d, true
	}
	if d, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return d, true
	}
	return nil, false
}

func uniqueIPs(a, b string) []string {
	if a == b {
		return []string{a}
	}
	return []string{a, b}
}

type pair struct{ user, pass string }

// pairUserPass mirrors the Python version: collect all USER lines and all PASS
// lines, then zip them together by index.
func pairUserPass(text string) []pair {
	users := reUser.FindAllStringSubmatch(text, -1)
	passes := rePass.FindAllStringSubmatch(text, -1)
	n := len(users)
	if len(passes) > n {
		n = len(passes)
	}
	var out []pair
	for i := 0; i < n; i++ {
		u, p := "?", "?"
		if i < len(users) {
			u = users[i][1]
		}
		if i < len(passes) {
			p = passes[i][1]
		}
		if u != "?" || p != "?" {
			out = append(out, pair{u, p})
		}
	}
	return out
}

func extractIMAP(text string) []pair {
	var out []pair
	for _, m := range reImap.FindAllStringSubmatch(text, -1) {
		out = append(out, pair{m[1], m[2]})
	}
	return out
}

func extractHTTPBasic(text string) []pair {
	var out []pair
	for _, m := range reBasic.FindAllStringSubmatch(text, -1) {
		if dec, ok := b64decode(m[1]); ok {
			if i := bytes.IndexByte(dec, ':'); i >= 0 {
				out = append(out, pair{string(dec[:i]), string(dec[i+1:])})
			}
		}
	}
	return out
}

func extractSMTP(text string) []pair {
	var out []pair
	for _, m := range reAuthPlain.FindAllStringSubmatch(text, -1) {
		if dec, ok := b64decode(m[1]); ok {
			parts := strings.Split(string(dec), "\x00")
			if len(parts) == 3 {
				out = append(out, pair{parts[1], parts[2]})
			}
		}
	}
	for _, m := range reAuthLogin.FindAllStringSubmatch(text, -1) {
		u, uok := b64decode(m[1])
		p, pok := b64decode(m[2])
		if uok && pok {
			out = append(out, pair{string(u), string(p)})
		}
	}
	return out
}

// extractTelnet is best-effort only; see the Python version's note on why
// Telnet rarely reassembles cleanly.
func extractTelnet(text string) []pair {
	var out []pair
	for _, m := range reTelnet.FindAllStringSubmatch(text, -1) {
		out = append(out, pair{strings.TrimSpace(m[1]), strings.TrimSpace(m[2])})
	}
	return out
}

func extractByProto(proto, text string) []pair {
	switch proto {
	case "ftp", "pop3":
		return pairUserPass(text)
	case "imap":
		return extractIMAP(text)
	case "http":
		return extractHTTPBasic(text)
	case "smtp":
		return extractSMTP(text)
	case "telnet":
		return extractTelnet(text)
	}
	return nil
}

// tcpTuple pulls the IPs, ports, and TCP payload out of a decoded packet.
// Shared by the file path and the live TZSP path.
func tcpTuple(packet gopacket.Packet) (ipA, ipB string, portA, portB int, payload []byte, ok bool) {
	nl := packet.NetworkLayer()
	tl := packet.Layer(layers.LayerTypeTCP)
	if nl == nil || tl == nil {
		return
	}
	tcp, o := tl.(*layers.TCP)
	if !o || len(tcp.Payload) == 0 {
		return
	}
	s, d := nl.NetworkFlow().Endpoints()
	return s.String(), d.String(), int(tcp.SrcPort), int(tcp.DstPort), tcp.Payload, true
}

// Analyze parses pcap/pcapng bytes and returns any recovered cleartext creds.
func Analyze(data []byte) ([]Credential, error) {
	flows, err := loadStreams(data)
	if err != nil {
		return nil, err
	}

	var findings []Credential
	for _, fd := range flows {
		proto := guessProto(fd.portA, fd.portB)
		if proto == "" {
			continue
		}
		for _, pr := range extractByProto(proto, fd.buf.String()) {
			findings = append(findings, Credential{
				Protocol: proto,
				Flow:     fd.label,
				Username: pr.user,
				Password: pr.pass,
				IPs:      uniqueIPs(fd.ipA, fd.ipB),
			})
		}
	}
	return findings, nil
}
