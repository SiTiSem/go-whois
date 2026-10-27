package whois

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

//go:embed whois.servers.json
var defaultServersJSON []byte

// Client performs WHOIS queries using a server map and network settings.
type Client struct {
	servers map[string][]string
	port    int
	timeout time.Duration
}

// Result contains a WHOIS response and the availability marker for its zone.
type Result struct {
	// Raw is the complete WHOIS response, including any referral response.
	Raw string

	noMatch string
}

// String returns the raw WHOIS response.
func (r Result) String() string {
	return r.Raw
}

// IsDomainAvailable checks the response using the zone's "no match" string
// without making network queries. It returns ErrNoMatchString when no marker
// is configured, including for IP and AS queries.
func (r Result) IsDomainAvailable() (bool, error) {
	if strings.TrimSpace(r.noMatch) == "" {
		return false, ErrNoMatchString
	}
	return strings.Contains(strings.ToLower(r.Raw), strings.ToLower(r.noMatch)), nil
}

const defaultTimeout = 10 * time.Second

// NewClient creates a WHOIS client and loads the embedded server list.
func NewClient() (*Client, error) {
	client := &Client{port: 43, timeout: defaultTimeout}
	if err := client.loadDefaultServers(); err != nil {
		return nil, err
	}
	return client, nil
}

// NewClientWithServers creates a WHOIS client and loads servers from a file.
func NewClientWithServers(path string) (*Client, error) {
	client := &Client{port: 43, timeout: defaultTimeout}
	if err := client.loadServers(path); err != nil {
		return nil, err
	}
	return client, nil
}

func (c *Client) loadDefaultServers() error {
	return c.loadServersFromBytes(defaultServersJSON)
}

func (c *Client) loadServers(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return c.loadServersFromBytes(data)
}

func (c *Client) loadServersFromBytes(data []byte) error {
	return json.Unmarshal(data, &c.servers)
}

// SetPort sets the default WHOIS port (default is 43).
func (c *Client) SetPort(port int) error {
	if port <= 0 || port > 65535 {
		return ErrInvalidPort
	}
	c.port = port
	return nil
}

// SetTimeout sets the dial and read/write timeout.
func (c *Client) SetTimeout(timeout time.Duration) error {
	if timeout <= 0 {
		return ErrInvalidTimeout
	}
	c.timeout = timeout
	return nil
}

// Whois performs a WHOIS query for a domain, IP address, or AS number.
func (c *Client) Whois(domain string) (*Result, error) {
	domain = strings.TrimSpace(domain)
	if ip := net.ParseIP(domain); ip != nil {
		return c.queryResult(ip.String(), "whois.iana.org", "")
	}
	if asn, ok := parseAS(domain); ok {
		return c.queryResult(asn, "whois.iana.org", "")
	}
	domain, entry, err := c.domainServerEntry(domain)
	if err != nil {
		return nil, err
	}

	var noMatch string
	if len(entry) > 1 {
		noMatch = entry[1]
	}
	return c.queryResult(domain, entry[0], noMatch)
}

// IsDomainAvailable checks availability using the "no match" string from the server entry.
func (c *Client) IsDomainAvailable(domain string) (bool, error) {
	domain, entry, err := c.domainServerEntry(domain)
	if err != nil {
		return false, err
	}
	if len(entry) < 2 || strings.TrimSpace(entry[1]) == "" {
		return false, ErrNoMatchString
	}

	result, err := c.queryResult(domain, entry[0], entry[1])
	if err != nil {
		return false, err
	}

	return result.IsDomainAvailable()
}

func (c *Client) domainServerEntry(domain string) (string, []string, error) {
	domain = strings.TrimSpace(domain)
	if c.servers == nil {
		return "", nil, ErrServersNotLoaded
	}
	asciiDomain, err := normalizeDomain(domain)
	if err != nil {
		return "", nil, err
	}
	if err := validateDomain(asciiDomain); err != nil {
		return "", nil, err
	}
	domain = strings.ToLower(asciiDomain)

	entry, tld, ok := c.findServerEntry(domain)
	if !ok || len(entry) == 0 {
		return "", nil, fmt.Errorf("no WHOIS server for zone %s", tld)
	}
	return domain, entry, nil
}

func validateDomain(domain string) error {
	if domain == "" {
		return ErrEmptyDomain
	}
	if strings.ContainsAny(domain, " \t\r\n") {
		return ErrDomainSpaces
	}
	return validateDomainLabels(domain)
}

func normalizeDomain(domain string) (string, error) {
	if domain == "" {
		return "", ErrEmptyDomain
	}
	if strings.ContainsAny(domain, " \t\r\n") {
		return "", ErrDomainSpaces
	}
	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", ErrDomainIDNA
	}
	return ascii, nil
}

func validateDomainLabels(domain string) error {
	if len(domain) > 253 {
		return ErrDomainLength
	}
	labels := strings.Split(strings.ToLower(domain), ".")
	if len(labels) < 2 {
		return ErrDomainMissingTLD
	}
	for _, label := range labels {
		if label == "" {
			return ErrDomainEmptyLabel
		}
		if len(label) > 63 {
			return ErrDomainLabelLength
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return ErrDomainLabelHyphen
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' {
				continue
			}
			return ErrDomainInvalidChar
		}
	}
	return nil
}

func (c *Client) findServerEntry(domain string) ([]string, string, bool) {
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts); i++ {
		tld := strings.Join(parts[i:], ".")
		if entry, ok := c.servers[tld]; ok {
			return entry, tld, true
		}
	}
	return nil, parts[len(parts)-1], false
}

func (c *Client) queryResult(domain, server, noMatch string) (*Result, error) {
	text, err := c.queryServerWithPort(domain, server, "")
	if err != nil {
		return nil, err
	}

	for _, line := range strings.Split(text, "\n") {
		ref, ok := strings.CutPrefix(strings.TrimSpace(line), "ReferralServer:")
		if !ok {
			continue
		}
		refHost, refPort := parseReferralServer(ref)
		more, err := c.queryServerWithPort(domain, refHost, refPort)
		if err == nil {
			text += "\n\n" + more
		}
		break
	}

	return &Result{Raw: text, noMatch: noMatch}, nil
}

func (c *Client) queryServerWithPort(domain, server, port string) (string, error) {
	if server == "" {
		return "", fmt.Errorf("invalid WHOIS server")
	}
	if port == "" {
		port = strconv.Itoa(c.port)
	}
	timeout := c.timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	conn, err := (&net.Dialer{Timeout: timeout}).Dial("tcp", net.JoinHostPort(server, port))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	_, err = conn.Write([]byte(domain + "\r\n"))
	if err != nil {
		return "", err
	}

	response, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}

	return string(response), nil
}

func parseReferralServer(ref string) (string, string) {
	ref = strings.TrimSpace(ref)
	ref = strings.TrimPrefix(ref, "whois://")
	if idx := strings.Index(ref, "/"); idx >= 0 {
		ref = ref[:idx]
	}
	if strings.HasPrefix(ref, "[") {
		host, port, err := net.SplitHostPort(ref)
		if err == nil {
			return host, port
		}
		return strings.Trim(ref, "[]"), ""
	}
	if strings.Count(ref, ":") == 1 {
		parts := strings.SplitN(ref, ":", 2)
		return parts[0], parts[1]
	}
	return ref, ""
}

func parseAS(input string) (string, bool) {
	s := strings.TrimSpace(strings.ToUpper(input))
	if len(s) < 3 || !strings.HasPrefix(s, "AS") {
		return "", false
	}
	for i := 2; i < len(s); i++ {
		ch := s[i]
		if ch < '0' || ch > '9' {
			return "", false
		}
	}
	return s, true
}
