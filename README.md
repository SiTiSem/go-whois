# go-whois

Minimal WHOIS client with an embedded server list and support for custom server maps.

## Install

```bash
go get github.com/SiTiSem/go-whois
```

## Requirements

- Go 1.24+.

## Usage

```go
package main

import (
	"fmt"
	"log"

	"github.com/SiTiSem/go-whois"
)

func main() {
	client, err := whois.NewClient()
	if err != nil {
		log.Fatal(err)
	}

	result, err := client.Whois("example.com")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(result)
}
```

## Availability

Use the "no match" string from the server list to check availability:

```go
available, err := client.IsDomainAvailable("example.com")
if err != nil {
	log.Fatal(err)
}
if available {
	fmt.Println("available")
}
```

`Whois` returns a `*whois.Result`. Check availability directly on that result
without another network query:

```go
result, err := client.Whois("example.com")
if err != nil {
	log.Fatal(err)
}
available, err := result.IsDomainAvailable()
if err != nil {
	log.Fatal(err)
}
if available {
	fmt.Println("available")
}
```

Use `result.Raw` or `result.String()` to access the response text. Printing the
result with `fmt.Println(result)` also prints the response text. Code that
previously used the return value of `Whois` as a string must now use `result.Raw`.

Both availability methods match the zone's "no match" string without regard to
case and return `ErrNoMatchString` if the zone has no availability marker.
`Whois` still returns the response for zones without a marker, as well as for IP
and AS queries; availability checking for these results returns `ErrNoMatchString`.

## Custom server list

Load servers from a JSON file on disk:

```go
client, err := whois.NewClientWithServers("whois.servers.json")
if err != nil {
	log.Fatal(err)
}
```

Server JSON format:

```json
{
  "tv": ["whois.nic.tv", "No match for"],
  "tv.br": ["whois.nic.br", "No match for"],
  "tw": ["whois.twnic.net.tw", "No Found"]
}
```

The first element is the WHOIS server hostname. The second element is an optional
"no match" string used by `IsDomainAvailable`.

## Port

Default port is 43. You can override it globally:

```go
client, err := whois.NewClient()
if err != nil {
	log.Fatal(err)
}
if err := client.SetPort(43); err != nil {
	log.Fatal(err)
}
```

## Timeout

Default timeout is 10s (dial + read/write). You can override it:

```go
client, err := whois.NewClient()
if err != nil {
	log.Fatal(err)
}
if err := client.SetTimeout(5 * time.Second); err != nil {
	log.Fatal(err)
}
```

## Notes

- IDN domains are converted to punycode automatically before lookup.
- Multi-level zones are supported (longest suffix match wins).
- IP and AS (e.g. `AS60614`) queries are supported via `whois.iana.org`.
