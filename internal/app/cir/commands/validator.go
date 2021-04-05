package commands

import (
	"fmt"
	"net"
)

// Validator - used to validate arguments
type Validator struct{}

// ArgValidator - global instance of validator
var ArgValidator = &Validator{}

// ValidateIP - validates IP - will only return true if correct IPV4
func (*Validator) ValidateIP(ip string, paramName string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		fmt.Printf("%s unable to parse ip\n", paramName)
		return false
	}

	if parsedIP.To4() == nil {
		fmt.Printf("%s param is ipv6 - not supported yet\n", paramName)
		return false
	}

	return true
}
