package whois

import "errors"

var (
	// ErrServersNotLoaded indicates the server map was not loaded.
	ErrServersNotLoaded = errors.New("servers are not loaded, create a client with NewClient or NewClientWithServers")
	// ErrEmptyDomain indicates an empty domain input.
	ErrEmptyDomain = errors.New("empty domain")
	// ErrDomainSpaces indicates the domain contains spaces.
	ErrDomainSpaces = errors.New("invalid domain: spaces")
	// ErrDomainEdgeDot indicates a leading or trailing dot.
	ErrDomainEdgeDot = errors.New("invalid domain: leading or trailing dot")
	// ErrDomainMissingTLD indicates the domain lacks a TLD.
	ErrDomainMissingTLD = errors.New("invalid domain: missing TLD")
	// ErrDomainLength indicates the domain exceeds the max length.
	ErrDomainLength = errors.New("invalid domain: length")
	// ErrDomainEmptyLabel indicates an empty label between dots.
	ErrDomainEmptyLabel = errors.New("invalid domain: empty label")
	// ErrDomainLabelLength indicates a label exceeds the max length.
	ErrDomainLabelLength = errors.New("invalid domain: label length")
	// ErrDomainLabelHyphen indicates a leading or trailing hyphen in a label.
	ErrDomainLabelHyphen = errors.New("invalid domain: leading or trailing hyphen")
	// ErrDomainInvalidChar indicates a non-ASCII domain character.
	ErrDomainInvalidChar = errors.New("invalid domain: invalid character")
	// ErrDomainIDNA indicates the domain failed IDNA conversion.
	ErrDomainIDNA = errors.New("invalid domain: idna conversion")
	// ErrNoMatchString indicates the server entry lacks a "no match" string.
	ErrNoMatchString = errors.New("no match string for zone")
	// ErrInvalidPort indicates a port outside the allowed range.
	ErrInvalidPort = errors.New("invalid port")
	// ErrInvalidTimeout indicates a timeout that is zero or negative.
	ErrInvalidTimeout = errors.New("invalid timeout")
)
