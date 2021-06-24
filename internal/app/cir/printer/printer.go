package printer

import (
	"fmt"
	"github.com/liamg/tml"
	"github.com/michal-franc/cir/internal/app/cir/analyser"
)

func printRedGreen(message string, b bool) {
	if b {
		tml.Printf("<green>✓</green> %s\n", message)
	} else {
		tml.Printf("<red>×</red> %s\n", message)
	}
}

func printCheck(c analyser.Check) {
	if c.IsPassing {
		tml.Printf("<green>✓</green> -> %s\n", c.Reason)
	} else {
		tml.Printf("<red>×</red> -> %s\n", c.Reason)
	}
}

// PrintSummary - prints quick summary of list of analysis
func PrintSummary(listOfAnalysis []analyser.Analysis) {
	fmt.Println("\nSummary: (if you want more details use --detailed flag)")
	for _, a := range listOfAnalysis {
		printRedGreen(fmt.Sprintf("%s can reach %s", a.SourceID, a.DestinationID), a.CanTheyConnect())
	}
}

// PrintAnalysis - print the analysis for human consumption in cli :)
func PrintAnalysis(analysis analyser.Analysis, detailed bool) {
	if analysis.CanTheyConnect() && !detailed {
		return
	}

	tml.Printf("<yellow>Check if %s can reach %s on port %d</yellow>\n", analysis.SourceID, analysis.DestinationID, analysis.DestinationPort)
	tml.Println("<yellow>---------------------------</yellow>")

	if analysis.AreInTheSameVpc {
		tml.Println("(source and dest - in the same vpc)")
	} else {
		tml.Println("(source and dest - in different vpcs)")
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
	tml.Println("<yellow>---------------------------</yellow>")
}
