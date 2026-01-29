package whois

import (
	"bufio"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func startWhoisServer(t *testing.T, response string, onQuery func(string)) (host string, port string, stop func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	stop = func() {
		_ = ln.Close()
	}
	t.Cleanup(stop)

	tcpLn := ln.(*net.TCPListener)
	_ = tcpLn.SetDeadline(time.Now().Add(2 * time.Second))

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

		reader := bufio.NewReader(conn)
		line, _ := reader.ReadString('\n')
		if onQuery != nil {
			onQuery(strings.TrimSpace(line))
		}

		_, _ = conn.Write([]byte(response))
	}()

	host, port, err = net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("addr: %v", err)
	}
	return host, port, stop
}

func TestWhoisNormalizesDomainCase(t *testing.T) {
	host, port, _ := startWhoisServer(t, "ok\n", func(q string) {
		if q != "example.com" {
			t.Errorf("expected query example.com, got %q", q)
		}
	})

	p, err := parsePort(port)
	if err != nil {
		t.Fatalf("port parse: %v", err)
	}

	c := &Client{
		servers: map[string][]string{"com": {host}},
		port:    p,
	}

	resp, err := c.Whois("Example.COM")
	if err != nil {
		t.Fatalf("whois: %v", err)
	}
	if !strings.Contains(resp, "ok") {
		t.Fatalf("expected ok response, got %q", resp)
	}
}

func TestWhoisIDNUsesPunycode(t *testing.T) {
	host, port, _ := startWhoisServer(t, "ok\n", func(q string) {
		if q != "xn--80a1acny.xn--p1ai" {
			t.Errorf("expected query xn--80a1acny.xn--p1ai, got %q", q)
		}
	})

	p, err := parsePort(port)
	if err != nil {
		t.Fatalf("port parse: %v", err)
	}

	c := &Client{
		servers: map[string][]string{"xn--p1ai": {host}},
		port:    p,
	}

	_, err = c.Whois("почта.рф")
	if err != nil {
		t.Fatalf("whois: %v", err)
	}
}

func TestIsDomainAvailable(t *testing.T) {
	host, port, _ := startWhoisServer(t, "No match for domain\n", nil)

	p, err := parsePort(port)
	if err != nil {
		t.Fatalf("port parse: %v", err)
	}

	c := &Client{
		servers: map[string][]string{"com": {host, "No match for"}},
		port:    p,
	}

	available, err := c.IsDomainAvailable("example.com")
	if err != nil {
		t.Fatalf("IsDomainAvailable: %v", err)
	}
	if !available {
		t.Fatalf("expected domain to be available")
	}
}

func TestIsDomainAvailableMissingMarker(t *testing.T) {
	host, port, _ := startWhoisServer(t, "No match for domain\n", nil)

	p, err := parsePort(port)
	if err != nil {
		t.Fatalf("port parse: %v", err)
	}

	c := &Client{
		servers: map[string][]string{"com": {host}},
		port:    p,
	}

	_, err = c.IsDomainAvailable("example.com")
	if err != ErrNoMatchString {
		t.Fatalf("expected ErrNoMatchString, got %v", err)
	}
}

func TestWhoisReferralWithPort(t *testing.T) {
	refHost, refPort, _ := startWhoisServer(t, "referral\n", nil)
	refLine := "ReferralServer: whois://" + refHost + ":" + refPort + "\n"
	primaryHost, primaryPort, _ := startWhoisServer(t, "primary\n"+refLine, nil)

	p, err := parsePort(primaryPort)
	if err != nil {
		t.Fatalf("port parse: %v", err)
	}

	c := &Client{
		servers: map[string][]string{"com": {primaryHost}},
		port:    p,
	}

	resp, err := c.Whois("example.com")
	if err != nil {
		t.Fatalf("whois: %v", err)
	}
	if !strings.Contains(resp, "primary") || !strings.Contains(resp, "referral") {
		t.Fatalf("expected combined response, got %q", resp)
	}
}

func parsePort(port string) (int, error) {
	return strconv.Atoi(port)
}

func TestParseAS(t *testing.T) {
	cases := []struct {
		input string
		want  string
		ok    bool
	}{
		{"AS60614", "AS60614", true},
		{"as123", "AS123", true},
		{" AS42 ", "AS42", true},
		{"AS", "", false},
		{"AS12A", "", false},
		{"12345", "", false},
	}

	for _, tc := range cases {
		got, ok := parseAS(tc.input)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("parseAS(%q) = (%q, %v), want (%q, %v)", tc.input, got, ok, tc.want, tc.ok)
		}
	}
}
