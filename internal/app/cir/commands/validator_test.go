package commands

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestInvalidIPsReturnFalse(t *testing.T) {

	invalidIPs := []string{
		"1.1.-1",          // -1
		"256.122.122.122", // 256 is > than max for ip 255
		"invalid",         // text is not ip
	}

	for _, ip := range invalidIPs {
		//TODO: remove fmt priints from ValidateIP so that we can remove paramName from here and simplify the function
		result := ArgValidator.ValidateIP(ip, "")
		assert.False(t, result)
	}
}

func TestValidIPsReturnTrue(t *testing.T) {

	validIPs := []string{
		"0.0.0.0", // this is valid IP - TODO: but maybe we should not allow it?
		"255.255.255.255",
		"192.168.0.1",
	}

	for _, ip := range validIPs {
		//TODO: remove fmt priints from ValidateIP so that we can remove paramName from here and simplify the function
		result := ArgValidator.ValidateIP(ip, "")
		assert.True(t, result)
	}
}
