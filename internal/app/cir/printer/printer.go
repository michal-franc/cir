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

func PrintAnalysis(analysis analyser.Analysis) {
	if analysis.AreInTheSameVpc {
		tml.Println("(same vpc)")
	} else {
		tml.Println("(different vpcs)")
	}

	if analysis.CanEscapeSource {
		tml.Println("<green>✓</green> -> sg - there is an outbound rule for source")
	} else {
		tml.Println("<red>×</red> -> sg - there is no outbound rule for source")
	}

	if analysis.SourceSubnetHasRoute {
		tml.Println("<green>✓</green> -> route - there is a route to destination in route table")
	} else {
		tml.Println("<red>×</red> -> route - there is no route to destination in route table")
	}

	if !analysis.AreInTheSameVpc {
		if analysis.ConnectionBetweenVPCsIsValid {
			tml.Printf("<green>✓</green> -> %s\n", analysis.ConnectionBetweenVPCsIsValidReason)
		} else {
			tml.Println("<red>×</red> -> %s\\n\", analysis.ConnectionBetweenVPCsIsValidReason")
		}
	}

	if analysis.DestinationSubnetHasRoute {
		tml.Println("<green>✓</green> -> route - there is a route from source in route table")
	} else {
		tml.Println("<red>×</red> -> route - there is no route from source in route table")
	}

	if analysis.CanEnterDestination {
		tml.Println("<green>✓</green> -> sg - there is an inbound rule for destination")
	} else {
		tml.Println("<red>×</red> -> sg - there is no inbound rule for destination")
	}
}
