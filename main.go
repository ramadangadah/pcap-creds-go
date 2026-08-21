package main

import (
	"crypto/rand"
	"embed"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed templates/*.html
var tmplFS embed.FS

//go:embed static/style.css
var staticFS embed.FS

var (
	maxUploadMB  = envInt("MAX_UPLOAD_MB", 200)
	cookieSecure = truthy(env("COOKIE_SECURE", "false"))
	dataDir      = env("DATA_DIR", "./data")
	liveEnabled  = truthy(env("LIVE_CAPTURE", "false"))
	livePort     = envInt("LIVE_PORT", 37008)
	liveBind     = env("LIVE_BIND", "0.0.0.0")
	allowedSrc   = env("ALLOWED_SOURCES", "")
	blockedSrc   = env("BLOCKED_SOURCES", "")
	templates    *template.Template
	store        *Store
	liveMgr      *LiveManager
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func truthy(v string) bool {
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// --- in-memory sessions --------------------------------------------------

type session struct {
	authed  bool
	scanMsg string
}

var (
	sessions   = map[string]*session{}
	sessionsMu sync.RWMutex
)

func newSessionID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func getSession(r *http.Request) (string, *session) {
	c, err := r.Cookie("sid")
	if err != nil {
		return "", nil
	}
	sessionsMu.RLock()
	s := sessions[c.Value]
	sessionsMu.RUnlock()
	return c.Value, s
}

func startSession(w http.ResponseWriter) *session {
	id := newSessionID()
	s := &session{authed: true}
	sessionsMu.Lock()
	sessions[id] = s
	sessionsMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: "sid", Value: id, Path: "/",
		HttpOnly: true, Secure: cookieSecure, SameSite: http.SameSiteLaxMode,
		MaxAge: 14 * 24 * 3600,
	})
	return s
}

func authed(r *http.Request) *session {
	_, s := getSession(r)
	if s != nil && s.authed {
		return s
	}
	return nil
}

// --- view data -----------------------------------------------------------

type dashData struct {
	User     string
	Stats    StatsData
	Findings []Finding
	ScanMsg  string
	Live     LiveStatus
}

// --- handlers ------------------------------------------------------------

func handleSetupForm(w http.ResponseWriter, r *http.Request) {
	if store.IsSetup() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	render(w, "setup.html", map[string]any{"Error": ""})
}

func handleSetup(w http.ResponseWriter, r *http.Request) {
	if store.IsSetup() {
		http.Error(w, "setup already completed", http.StatusForbidden)
		return
	}
	user := strings.TrimSpace(r.FormValue("username"))
	pw := r.FormValue("password")
	confirm := r.FormValue("confirm")

	var errMsg string
	switch {
	case user == "":
		errMsg = "Username is required."
	case len(pw) < 8:
		errMsg = "Password must be at least 8 characters."
	case pw != confirm:
		errMsg = "Passwords do not match."
	}
	if errMsg != "" {
		w.WriteHeader(http.StatusBadRequest)
		render(w, "setup.html", map[string]any{"Error": errMsg})
		return
	}

	if err := store.CreateAdmin(user, pw); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render(w, "setup.html", map[string]any{"Error": "Could not save account: " + err.Error()})
		return
	}
	startSession(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if !store.IsSetup() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	render(w, "login.html", map[string]any{"Error": ""})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if !store.IsSetup() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	user := strings.TrimSpace(r.FormValue("username"))
	pw := r.FormValue("password")
	if store.CheckLogin(user, pw) {
		startSession(w)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
	render(w, "login.html", map[string]any{"Error": "Incorrect username or password"})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if id, s := getSession(r); s != nil {
		sessionsMu.Lock()
		delete(sessions, id)
		sessionsMu.Unlock()
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if !store.IsSetup() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	s := authed(r)
	if s == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	msg := s.scanMsg
	s.scanMsg = "" // consume flash
	render(w, "dashboard.html", dashData{
		User:     store.AdminUser(),
		Stats:    store.Stats(),
		Findings: store.AllFindings(),
		ScanMsg:  msg,
		Live:     liveMgr.Status(),
	})
}

func handleAnalyze(w http.ResponseWriter, r *http.Request) {
	s := authed(r)
	if s == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	maxBytes := int64(maxUploadMB) * 1024 * 1024
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes+4096)
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		s.scanMsg = fmt.Sprintf("Upload failed: too large (limit %d MB).", maxUploadMB)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	file, header, err := r.FormFile("pcap_file")
	if err != nil {
		s.scanMsg = "Upload failed: no file provided."
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file) // parsed in memory, never written to disk
	if err != nil {
		s.scanMsg = "Upload failed: could not read file."
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	results, err := Analyze(data)
	if err != nil {
		s.scanMsg = "Parse failed: " + err.Error()
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	newUnique, merged := store.Merge(results)
	s.scanMsg = fmt.Sprintf("%s: %d credentials parsed \u2014 %d new, %d duplicates merged.",
		header.Filename, len(results), newUnique, merged)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleClear(w http.ResponseWriter, r *http.Request) {
	s := authed(r)
	if s == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	_ = store.Clear()
	s.scanMsg = "All findings cleared."
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleBlock(w http.ResponseWriter, r *http.Request) {
	s := authed(r)
	if s == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	entry := strings.TrimSpace(r.FormValue("entry"))
	if norm, err := store.AddBlock(entry); err != nil {
		s.scanMsg = fmt.Sprintf("Could not block %q: not a valid IP or CIDR.", entry)
	} else {
		if liveMgr != nil {
			liveMgr.RebuildBlocked()
		}
		s.scanMsg = "Blocked source " + norm + "."
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleUnblock(w http.ResponseWriter, r *http.Request) {
	s := authed(r)
	if s == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	entry := strings.TrimSpace(r.FormValue("entry"))
	_ = store.RemoveBlock(entry)
	if liveMgr != nil {
		liveMgr.RebuildBlocked()
	}
	s.scanMsg = "Unblocked source " + entry + "."
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func stem(name string) string {
	base := filepath.Base(name)
	if base == "" || base == "." {
		return "findings"
	}
	if e := filepath.Ext(base); e != "" {
		return strings.TrimSuffix(base, e)
	}
	return base
}

func handleExportTxt(w http.ResponseWriter, r *http.Request) {
	if authed(r) == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	findings := store.AllFindings()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="findings.txt"`)
	if len(findings) == 0 {
		fmt.Fprintln(w, "No cleartext credentials found.")
		return
	}
	for _, f := range findings {
		fmt.Fprintf(w, "[%s] user=%s  pass=%s  seen=%d  ips=%s\n",
			strings.ToUpper(strings.Join(f.Protocols, ",")),
			f.Username, f.Password, f.Count, strings.Join(f.IPs, ","))
	}
}

func handleExportCSV(w http.ResponseWriter, r *http.Request) {
	if authed(r) == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	findings := store.AllFindings()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="findings.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"protocols", "username", "password", "count", "ips", "flows"})
	for _, f := range findings {
		_ = cw.Write([]string{
			strings.Join(f.Protocols, "|"),
			f.Username, f.Password,
			strconv.Itoa(f.Count),
			strings.Join(f.IPs, "|"),
			strings.Join(f.Flows, "|"),
		})
	}
	cw.Flush()
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":"ok"}`)
}

// --- helpers -------------------------------------------------------------

func render(w http.ResponseWriter, name string, data any) {
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("template error (%s): %v", name, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func main() {
	var err error
	store, err = NewStore(dataDir)
	if err != nil {
		log.Fatalf("cannot open data dir %q: %v", dataDir, err)
	}
	templates = template.Must(template.ParseFS(tmplFS, "templates/*.html"))

	if liveEnabled {
		liveMgr = NewLiveManager(store, liveBind, livePort, allowedSrc, blockedSrc)
		go func() {
			if err := liveMgr.Start(); err != nil {
				log.Printf("live capture disabled: %v", err)
				liveMgr = nil
			}
		}()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /setup", handleSetupForm)
	mux.HandleFunc("POST /setup", handleSetup)
	mux.HandleFunc("GET /login", handleLoginForm)
	mux.HandleFunc("POST /login", handleLogin)
	mux.HandleFunc("GET /logout", handleLogout)
	mux.HandleFunc("GET /", handleIndex)
	mux.HandleFunc("POST /analyze", handleAnalyze)
	mux.HandleFunc("POST /clear", handleClear)
	mux.HandleFunc("POST /block", handleBlock)
	mux.HandleFunc("POST /unblock", handleUnblock)
	mux.HandleFunc("GET /export/txt", handleExportTxt)
	mux.HandleFunc("GET /export/csv", handleExportCSV)
	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("GET /static/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		b, _ := staticFS.ReadFile("static/style.css")
		w.Write(b)
	})

	addr := ":" + env("PORT", "8000")
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("PCAP Credential Auditor (Go) listening on %s  data=%s", addr, dataDir)
	log.Fatal(srv.ListenAndServe())
}
