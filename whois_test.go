package whois

import (
	"bufio"
	"fmt"
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
	if resp.Raw != "ok\n" || resp.String() != resp.Raw || fmt.Sprint(resp) != resp.Raw {
		t.Fatalf("expected raw ok response, got %#v", resp)
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

func TestResultIsDomainAvailableAfterWhois(t *testing.T) {
	host, port, stop := startWhoisServer(t, "No match for domain\n", nil)
	p, err := parsePort(port)
	if err != nil {
		t.Fatalf("port parse: %v", err)
	}
	c := &Client{
		servers: map[string][]string{"com": {host, "No match for"}},
		port:    p,
	}

	response, err := c.Whois("example.com")
	if err != nil {
		t.Fatalf("Whois: %v", err)
	}
	stop()
	// The result must retain its marker independently of later client changes.
	c.servers["com"][1] = "different marker"

	available, err := response.IsDomainAvailable()
	if err != nil {
		t.Fatalf("IsDomainAvailable: %v", err)
	}
	if !available {
		t.Fatal("expected domain to be available with server stopped")
	}
}

func TestResultIsDomainAvailable(t *testing.T) {
	cases := []struct {
		name     string
		domain   string
		response string
		want     bool
	}{
		{"available", "example.com", "No match for domain\n", true},
		{"registered", "example.com", "Domain Name: EXAMPLE.COM\n", false},
		{"case and whitespace", " Example.COM ", "NO MATCH FOR domain\n", true},
		{"IDN", "почта.рф", "NO ENTRIES FOUND\n", true},
		{"longest zone", "example.tv.br", "No match for domain\n", true},
		{"parent marker ignored", "example.tv.br", "Not found\n", false},
		{"empty response", "example.com", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port, _ := startWhoisServer(t, tc.response, nil)
			p, err := parsePort(port)
			if err != nil {
				t.Fatalf("port parse: %v", err)
			}
			c := &Client{servers: map[string][]string{
				"com":      {host, "No match for"},
				"xn--p1ai": {host, "No entries found"},
				"br":       {host, "Not found"},
				"tv.br":    {host, "No match for"},
			}, port: p}
			result, err := c.Whois(tc.domain)
			if err != nil {
				t.Fatalf("Whois: %v", err)
			}
			got, err := result.IsDomainAvailable()
			if err != nil {
				t.Fatalf("IsDomainAvailable: %v", err)
			}
			if got != tc.want {
				t.Fatalf("availability = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWhoisErrors(t *testing.T) {
	cases := []struct {
		name    string
		servers map[string][]string
		domain  string
		wantErr error
	}{
		{"servers not loaded", nil, "example.com", ErrServersNotLoaded},
		{"empty domain", map[string][]string{}, "", ErrEmptyDomain},
		{"domain spaces", map[string][]string{}, "exam ple.com", ErrDomainSpaces},
		{"missing TLD", map[string][]string{}, "example", ErrDomainMissingTLD},
		{"unknown zone", map[string][]string{}, "example.com", nil},
		{"empty entry", map[string][]string{"com": {}}, "example.com", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{servers: tc.servers}
			result, err := c.Whois(tc.domain)
			if result != nil {
				t.Fatal("expected nil result on error")
			}
			if tc.wantErr != nil {
				if err != tc.wantErr {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}
			} else if err == nil || err.Error() != "no WHOIS server for zone com" {
				t.Fatalf("expected missing server error for com, got %v", err)
			}
		})
	}
}

func TestResultIsDomainAvailableMissingMarker(t *testing.T) {
	for _, marker := range []string{"", " \t"} {
		t.Run(fmt.Sprintf("marker=%q", marker), func(t *testing.T) {
			host, port, _ := startWhoisServer(t, "raw response\n", nil)
			p, err := parsePort(port)
			if err != nil {
				t.Fatalf("port parse: %v", err)
			}
			entry := []string{host}
			if marker != "" {
				entry = append(entry, marker)
			}
			c := &Client{servers: map[string][]string{"com": entry}, port: p}
			result, err := c.Whois("example.com")
			if err != nil {
				t.Fatalf("Whois without availability marker: %v", err)
			}
			available, err := result.IsDomainAvailable()
			if available || err != ErrNoMatchString {
				t.Fatalf("IsDomainAvailable = (%v, %v), want (false, ErrNoMatchString)", available, err)
			}
		})
	}
	var result Result
	if available, err := result.IsDomainAvailable(); available || err != ErrNoMatchString {
		t.Fatalf("zero result availability = (%v, %v), want (false, ErrNoMatchString)", available, err)
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
	if !strings.Contains(resp.Raw, "primary") || !strings.Contains(resp.Raw, "referral") {
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
