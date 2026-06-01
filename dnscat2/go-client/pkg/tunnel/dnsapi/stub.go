//go:build !windows

// Package dnsapi is Windows-only. This stub allows the package to compile
// on other platforms so cmd/dnscat-dnsapi can be cross-compiled, but NewDriver
// returns an error at runtime.
package dnsapi

import "fmt"

type DNSType uint16

const (
	TypeA     DNSType = 1
	TypeCNAME DNSType = 5
	TypeMX    DNSType = 15
	TypeTXT   DNSType = 16
	TypeAAAA  DNSType = 28
)

// Driver is a non-functional stub on non-Windows platforms.
type Driver struct{}

func NewDriver(domain, host string, port uint16, types string, server string) (*Driver, error) {
	return nil, fmt.Errorf("dnsapi: DnsQuery_W transport is Windows-only")
}

func (d *Driver) Run()  {}
func (d *Driver) Close() {}
