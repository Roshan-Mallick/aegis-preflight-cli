package main

import (
	"errors"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func dnsServer(addr string) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		emit(logLine{Kind: "dns-fatal", Decision: "error", Reason: err.Error()})
		return
	}
	buf := make([]byte, 1500)
	for {
		n, cli, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		q := make([]byte, n)
		copy(q, buf[:n])
		go handleDNSQuery(pc, q, cli)
	}
}

func handleDNSQuery(pc net.PacketConn, query []byte, cli net.Addr) {
	var msg dnsmessage.Message
	if err := msg.Unpack(query); err != nil || len(msg.Questions) == 0 {
		return
	}
	q := msg.Questions[0]
	name := strings.TrimSuffix(q.Name.String(), ".")

	if !matcher.Match(name) {
		refused := dnsmessage.Message{
			ID:               msg.ID,
			Response:         true,
			RecursionDesired: msg.RecursionDesired,
			RCode:            dnsmessage.RCodeNameError,
			Questions:        msg.Questions,
		}
		if b, err := refused.Pack(); err == nil {
			_, _ = pc.WriteTo(b, cli)
		}
		emit(logLine{Kind: "dns", Domain: name, Decision: "block", Reason: "domain not in allowlist"})
		return
	}

	respBytes, err := exchangeUpstream(query)
	if err != nil {
		nx := dnsmessage.Message{
			ID:               msg.ID,
			Response:         true,
			RecursionDesired: msg.RecursionDesired,
			RCode:            dnsmessage.RCodeServerFailure,
			Questions:        msg.Questions,
		}
		if b, err := nx.Pack(); err == nil {
			_, _ = pc.WriteTo(b, cli)
		}
		emit(logLine{Kind: "dns", Domain: name, Decision: "block", Reason: "upstream lookup failed"})
		return
	}
	_, _ = pc.WriteTo(respBytes, cli)
	emit(logLine{Kind: "dns", Domain: name, Decision: "allow", Reason: "allowlisted domain resolved"})
}

func exchangeUpstream(query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(upstreamDNS, "53"), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := conn.(*net.UDPConn); ok {
		_ = deadline.SetReadDeadline(time.Now().Add(8 * time.Second))
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n >= 2 && buf[0] == query[0] && buf[1] == query[1] {
			return buf[:n], nil
		}
		if len(buf) < 2 {
			return nil, errors.New("short dns reply")
		}
	}
}
