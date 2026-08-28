package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/eth0x1/aegis/internal/network"
)

type logLine struct {
	Time     string `json:"time"`
	Kind     string `json:"kind"`
	Domain   string `json:"domain"`
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

var (
	out         *json.Encoder
	matcher     *network.Matcher
	upstreamDNS string
)

func emit(l logLine) {
	l.Time = time.Now().UTC().Format(time.RFC3339Nano)
	_ = out.Encode(&l)
}

func splitHostPort(hostport string) (string, int) {
	host := hostport
	port := 443
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		host = h
		if pp, aerr := strconv.Atoi(p); aerr == nil && pp > 0 {
			port = pp
		}
	}
	return strings.Trim(host, "[]"), port
}

func deny(w http.ResponseWriter, d network.Decision) {
	emit(logLine{Kind: "connect", Domain: d.Domain, IP: d.IP, Port: d.Port, Decision: "block", Reason: d.Reason})
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte("AEGIS-BLOCKED: " + d.Reason + "\n"))
}

func handleCONNECT(w http.ResponseWriter, r *http.Request) {
	host, port := splitHostPort(r.Host)
	d := network.Evaluate(matcher, host, port)
	if !d.Allow {
		deny(w, d)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer client.Close()

	target, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 15*time.Second)
	if err != nil {
		emit(logLine{Kind: "connect", Domain: host, Port: port, Decision: "block", Reason: "target dial failed"})
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer target.Close()
	ip := ""
	if ta, ok := target.RemoteAddr().(*net.TCPAddr); ok {
		ip = ta.IP.String()
	}
	emit(logLine{Kind: "connect", Domain: host, IP: ip, Port: port, Decision: "allow", Reason: d.Reason})

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, target); done <- struct{}{} }()
	<-done
}

func handlePlainHTTP(w http.ResponseWriter, r *http.Request) {
	u := r.URL
	if u.Host == "" {
		http.Error(w, "not a proxy request", http.StatusBadRequest)
		return
	}
	host, port := u.Hostname(), 80
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}
	d := network.Evaluate(matcher, host, port)
	if !d.Allow {
		deny(w, d)
		return
	}
	req := r.Clone(r.Context())
	req.RequestURI = ""
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		emit(logLine{Kind: "connect", Domain: host, Port: port, Decision: "block", Reason: "forward failed"})
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	emit(logLine{Kind: "connect", Domain: host, IP: d.IP, Port: port, Decision: "allow", Reason: d.Reason})
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func main() {
	out = json.NewEncoder(os.Stdout)
	allowRaw := os.Getenv("AEGIS_ALLOWLIST")
	if strings.TrimSpace(allowRaw) == "" {
		allowRaw = "api.anthropic.com"
	}
	matcher = network.NewMatcher(strings.Split(allowRaw, ","))
	upstreamDNS = os.Getenv("AEGIS_UPSTREAM_DNS")
	if upstreamDNS == "" {
		upstreamDNS = "1.1.1.1"
	}

	go dnsServer(":53")

	srv := &http.Server{
		Addr:              ":3128",
		ReadHeaderTimeout: 30 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleCONNECT(w, r)
				return
			}
			handlePlainHTTP(w, r)
		}),
	}
	if err := srv.ListenAndServe(); err != nil {
		emit(logLine{Kind: "fatal", Decision: "error", Reason: err.Error()})
		os.Exit(1)
	}
}
