package commands

import (
	"fmt"
	"net"
)

type Validator struct{}

var ArgValidator = &Validator{}

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
