package printer

import (
	"fmt"
	"github.com/liamg/tml"
	"github.com/michal-franc/cir/internal/app/cir/analyser"
)

func printRedGreen(message string, b bool) {
	if b {
		tml.Printf("<green>✓</green> -> %s\n", message)
	} else {
		tml.Printf("<red>×</red> -> %s\n", message)
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

	printRedGreen("security groups:", analysis.CanEnterDestination.IsPassing && analysis.CanEscapeSource.IsPassing)
	printCheck(*analysis.CanEscapeSource)
	printCheck(*analysis.CanEnterDestination)
	fmt.Println()
	printRedGreen("subnets:", analysis.SourceSubnetHasRoute.IsPassing && analysis.DestinationSubnetHasRoute.IsPassing)
	printCheck(*analysis.SourceSubnetHasRoute)
	if !analysis.AreInTheSameVpc { // display only dest subnet if diff vpc
		printCheck(*analysis.DestinationSubnetHasRoute)
	}
	fmt.Println()
	if !analysis.AreInTheSameVpc {
		printRedGreen("vpc connection:", analysis.ConnectionBetweenVPCsIsActive.IsPassing && analysis.ConnectionBetweenVPCsIsValid.IsPassing)
		printCheck(*analysis.ConnectionBetweenVPCsIsValid)
		printCheck(*analysis.ConnectionBetweenVPCsIsActive)
	}
}
