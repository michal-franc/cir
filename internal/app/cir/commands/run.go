package commands

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/michal-franc/cir/internal/app/cir/analyser"
	"github.com/michal-franc/cir/internal/app/cir/printer"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/michal-franc/cir/internal/app/cir/scanner"
)

var sourceQuery string
var destinationQuery string
var port int32
var debug bool
var detailed bool

func init() {
	startCmd.Flags().StringVar(&sourceQuery, "from", "", "Specifies which machine the communication is initiated from eg ip:127.0.0.0 or name:my-awesome-ec2.")
	startCmd.MarkFlagRequired("from")
	startCmd.Flags().StringVar(&destinationQuery, "to", "", "Specifies which machine the communication is destined to go to ip:127.0.0.0 or name:my-awesome-ec2.")
	startCmd.MarkFlagRequired("to")
	startCmd.Flags().Int32Var(&port, "port", -1, "Specifies which port should be checked.")
	startCmd.MarkFlagRequired("port")
	startCmd.Flags().BoolVar(&debug, "debug", false, "Specifies if debug messages should be emitted.")
	startCmd.Flags().BoolVar(&detailed, "detailed", false, "Will print detailed analysis regardless if there is one analysis or more.")
	rootCmd.AddCommand(startCmd)
}

func validateArgs() bool {
	isValid := true

	if port <= 0 || port > 65535 {
		fmt.Println("port value out of range 1-65535")
		isValid = false
	}

	if strings.Contains("from", "ip") {
		isValid = ArgValidator.ValidateIP(sourceQuery, "from") && isValid
	}
	if strings.Contains("to", "ip") {
		isValid = ArgValidator.ValidateIP(destinationQuery, "to") && isValid
	}

	return isValid
}

var startCmd = &cobra.Command{
	Use:   "run",
	Short: "run analysis",
	Run: func(cmd *cobra.Command, args []string) {
		if !validateArgs() {
			os.Exit(1)
		}

		log.SetLevel(log.WarnLevel)
		fmt.Printf("checking if '%s' can reach '%s on port '%d'\n", sourceQuery, destinationQuery, port)

		if debug {
			log.SetLevel(log.DebugLevel)
		}

		cfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			log.Fatalf("unable to load SDK config, %v", err)
		}

		creds, err := cfg.Credentials.Retrieve(context.Background())
		if err != nil {
			log.Fatal("no credentials or invalid credentials provided")
		}

		if creds.Expired() {
			log.Fatal("aws credentials have expired - aborting")
		}

		ec2Svc := ec2.NewFromConfig(cfg)
		data, err := scanner.ScanAwsEc2(ec2Svc, sourceQuery, destinationQuery)
		if err != nil {
			log.Fatalf("error when scanning AWS resources - %s", err)
		}

		listOfAnalysis, err := analyser.RunAnalysis(*data, ec2Svc, port)
		if err != nil {
			log.Fatalf("error when analysing data - %s", err)
		}

		for _, a := range listOfAnalysis {
			printer.PrintAnalysis(a, len(listOfAnalysis) <= 1 || detailed)
		}

		// we want to print summary at the end if there are more than one listOfAnalysis
		if len(listOfAnalysis) > 1 {
			printer.PrintSummary(listOfAnalysis)
		}
	},
}
