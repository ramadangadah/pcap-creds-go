package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var errInvalidEntry = errors.New("invalid IP or CIDR")

// Config holds the admin account created during first-run setup.
type Config struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	SetupDone    bool   `json:"setup_done"`
}

// Finding is one unique credential (deduplicated by username+password),
// enriched with everywhere it was observed.
type Finding struct {
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	Protocols []string  `json:"protocols"`
	Flows     []string  `json:"flows"`
	IPs       []string  `json:"ips"`
	Count     int       `json:"count"` // total times observed across all uploads
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Store is the on-disk state: admin config + accumulated findings. Both files
// are written 0600 because findings contain plaintext credentials.
type Store struct {
	mu       sync.RWMutex
	dir      string
	cfg      Config
	findings map[string]*Finding // key = username \x00 password
	order    []string
	blocked  []string // blocked source IPs/CIDRs (live capture)
}

func credKey(user, pass string) string { return user + "\x00" + pass }

func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, findings: map[string]*Finding{}}
	s.loadConfig()
	s.loadFindings()
	s.loadBlocked()
	return s, nil
}

func (s *Store) configPath() string   { return filepath.Join(s.dir, "config.json") }
func (s *Store) findingsPath() string { return filepath.Join(s.dir, "findings.json") }
func (s *Store) blockedPath() string  { return filepath.Join(s.dir, "blocked.json") }

func (s *Store) loadConfig() {
	b, err := os.ReadFile(s.configPath())
	if err != nil {
		return
	}
	_ = json.Unmarshal(b, &s.cfg)
}

func (s *Store) loadFindings() {
	b, err := os.ReadFile(s.findingsPath())
	if err != nil {
		return
	}
	var list []*Finding
	if json.Unmarshal(b, &list) != nil {
		return
	}
	for _, f := range list {
		k := credKey(f.Username, f.Password)
		s.findings[k] = f
		s.order = append(s.order, k)
	}
}

func (s *Store) saveConfig() error {
	b, _ := json.MarshalIndent(s.cfg, "", "  ")
	return os.WriteFile(s.configPath(), b, 0o600)
}

func (s *Store) saveFindings() error {
	list := make([]*Finding, 0, len(s.order))
	for _, k := range s.order {
		if f := s.findings[k]; f != nil {
			list = append(list, f)
		}
	}
	b, _ := json.MarshalIndent(list, "", "  ")
	return os.WriteFile(s.findingsPath(), b, 0o600)
}

// --- admin account -------------------------------------------------------

func (s *Store) IsSetup() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.SetupDone
}

func (s *Store) CreateAdmin(user, pass string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = Config{Username: user, PasswordHash: string(hash), SetupDone: true}
	return s.saveConfig()
}

func (s *Store) CheckLogin(user, pass string) bool {
	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()
	if !cfg.SetupDone || user != cfg.Username {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(cfg.PasswordHash), []byte(pass)) == nil
}

func (s *Store) AdminUser() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.Username
}

// --- findings ------------------------------------------------------------

func addUnique(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// Merge folds a fresh set of parsed credentials into the store, deduplicating
// by username+password. Returns how many were brand-new vs. merged into an
// existing record.
func (s *Store) Merge(creds []Credential) (newUnique, merged int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for _, c := range creds {
		k := credKey(c.Username, c.Password)
		f, ok := s.findings[k]
		if !ok {
			f = &Finding{Username: c.Username, Password: c.Password, FirstSeen: now}
			s.findings[k] = f
			s.order = append(s.order, k)
			newUnique++
		} else {
			merged++
		}
		f.Count++
		f.LastSeen = now
		f.Protocols = addUnique(f.Protocols, c.Protocol)
		f.Flows = addUnique(f.Flows, c.Flow)
		for _, ip := range c.IPs {
			f.IPs = addUnique(f.IPs, ip)
		}
	}
	_ = s.saveFindings()
	return
}

// AllFindings returns a copy sorted by occurrence count (desc), then recency.
func (s *Store) AllFindings() []Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Finding, 0, len(s.order))
	for _, k := range s.order {
		if f := s.findings[k]; f != nil {
			out = append(out, *f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}

func (s *Store) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findings = map[string]*Finding{}
	s.order = nil
	return s.saveFindings()
}

// --- blocklist (live capture sources) ------------------------------------

func (s *Store) loadBlocked() {
	b, err := os.ReadFile(s.blockedPath())
	if err != nil {
		return
	}
	_ = json.Unmarshal(b, &s.blocked)
}

func (s *Store) saveBlocked() error {
	b, _ := json.MarshalIndent(s.blocked, "", "  ")
	return os.WriteFile(s.blockedPath(), b, 0o600)
}

// normalizeCIDR accepts a bare IP or a CIDR and returns a canonical CIDR string.
func normalizeCIDR(entry string) (string, bool) {
	e := strings.TrimSpace(entry)
	if e == "" {
		return "", false
	}
	if !strings.Contains(e, "/") {
		if strings.Contains(e, ":") {
			e += "/128"
		} else {
			e += "/32"
		}
	}
	if _, n, err := net.ParseCIDR(e); err == nil {
		return n.String(), true
	}
	return "", false
}

func (s *Store) AddBlock(entry string) (string, error) {
	norm, ok := normalizeCIDR(entry)
	if !ok {
		return "", errInvalidEntry
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.blocked {
		if b == norm {
			return norm, nil // already present
		}
	}
	s.blocked = append(s.blocked, norm)
	return norm, s.saveBlocked()
}

func (s *Store) RemoveBlock(entry string) error {
	norm, ok := normalizeCIDR(entry)
	if !ok {
		norm = strings.TrimSpace(entry) // allow removing exactly-stored value
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.blocked[:0]
	for _, b := range s.blocked {
		if b != norm {
			out = append(out, b)
		}
	}
	s.blocked = out
	return s.saveBlocked()
}

func (s *Store) BlockedList() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.blocked))
	copy(out, s.blocked)
	return out
}

// --- stats ---------------------------------------------------------------

type IPCount struct {
	IP    string
	Count int
	Pct   int // 0..100, for bar width
}

type ProtoCount struct {
	Proto string
	Count int
}

type StatsData struct {
	TotalUnique      int
	TotalOccurrences int
	TopIPs           []IPCount
	Protocols        []ProtoCount
}

func (s *Store) Stats() StatsData {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ipCounts := map[string]int{}
	protoCounts := map[string]int{}
	total := 0

	for _, k := range s.order {
		f := s.findings[k]
		if f == nil {
			continue
		}
		total += f.Count
		for _, ip := range f.IPs {
			ipCounts[ip] += f.Count
		}
		for _, p := range f.Protocols {
			protoCounts[p]++
		}
	}

	var ips []IPCount
	max := 0
	for ip, c := range ipCounts {
		ips = append(ips, IPCount{IP: ip, Count: c})
		if c > max {
			max = c
		}
	}
	sort.SliceStable(ips, func(i, j int) bool {
		if ips[i].Count != ips[j].Count {
			return ips[i].Count > ips[j].Count
		}
		return ips[i].IP < ips[j].IP
	})
	if len(ips) > 10 {
		ips = ips[:10]
	}
	for i := range ips {
		if max > 0 {
			ips[i].Pct = ips[i].Count * 100 / max
		}
	}

	var protos []ProtoCount
	for p, c := range protoCounts {
		protos = append(protos, ProtoCount{Proto: p, Count: c})
	}
	sort.SliceStable(protos, func(i, j int) bool {
		if protos[i].Count != protos[j].Count {
			return protos[i].Count > protos[j].Count
		}
		return protos[i].Proto < protos[j].Proto
	})

	return StatsData{
		TotalUnique:      len(s.order),
		TotalOccurrences: total,
		TopIPs:           ips,
		Protocols:        protos,
	}
}
