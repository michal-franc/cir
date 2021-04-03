package printer

import (
	"github.com/liamg/tml"
	"github.com/michal-franc/cir/internal/app/cir/analyser"
)

// non verbose just print yey it can
// verbose
// vpc-123456 (same vpc)
// v -> sg - there is a outbound rule for source (ip)
// v -> route - there is a route to destination in route table (id) -> (cidr range or id of gateway)
// v -> route - there is a route from source in route table (id) -> (cidr range or id of gateway)
// v -> sg - there is inboud rule for destination (ip)

func printRedGreen(b bool, positive string, negative string) {
	if b {
		tml.Printf("<green>✓</green> -> %s\n", positive)
	} else {
		tml.Printf("<red>×</red> -> %s\n", negative)
	}
}

func printCheck(c analyser.Check) {
	if c.IsPassing {
		tml.Printf("<green>✓</green> -> %s\n", c.Reason)
	} else {
		tml.Printf("<red>×</red> -> %s\n", c.Reason)
	}
}

func PrintAnalysis(analysis analyser.Analysis) {
	if analysis.AreInTheSameVpc {
		tml.Println("(same vpc)")
	} else {
		tml.Println("(different vpcs)")
	}

	printCheck(*analysis.CanEscapeSource)
	printCheck(*analysis.SourceSubnetHasRoute)

	if !analysis.AreInTheSameVpc {
		printCheck(*analysis.ConnectionBetweenVPCsIsValid)
		printCheck(*analysis.ConnectionBetweenVPCsIsActive)
	}

	printCheck(*analysis.DestinationSubnetHasRoute)
	printCheck(*analysis.CanEnterDestination)
}
