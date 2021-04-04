package commands

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/michal-franc/cir/internal/app/cir/analyser"
	"github.com/michal-franc/cir/internal/app/cir/printer"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/michal-franc/cir/internal/app/cir/scanner"
)

var sourceIp string
var destinationIp string
var port int32
var debug bool

func init() {
	startCmd.Flags().StringVar(&sourceIp, "from", "", "Specifies which machine the communication is initiated from.")
	startCmd.Flags().StringVar(&destinationIp, "to", "", "Specifies which machine the communication is destined to go to.")
	startCmd.Flags().Int32Var(&port, "port", -1, "Specifies which port should be checked.")
	startCmd.Flags().BoolVar(&debug, "debug", false, "Specifies if debug messages should be emitted.")
	rootCmd.AddCommand(startCmd)
}

var startCmd = &cobra.Command{
	Use:   "run",
	Short: "run analysis",
	Run: func(cmd *cobra.Command, args []string) {
		log.SetLevel(log.WarnLevel)
		fmt.Printf("checking if '%s' can reach '%s on port '%d'\n", sourceIp, destinationIp, port)

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
		data, err := scanner.ScanAwsEc2(ec2Svc, sourceIp, destinationIp)
		if err != nil {
			log.Fatalf("Error when scannning looking for AWS resources - %s", err)
		}

		analysis, err := analyser.RunAnalysis(*data, ec2Svc, port)
		if err != nil {
			log.Fatalf("Error when analysing data - %s", err)
		}

		printer.PrintAnalysis(*analysis)
	},
}
