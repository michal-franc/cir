package commands

import (
	"github.com/spf13/cobra"

	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	log "github.com/sirupsen/logrus"
	"net"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/liamg/tml"
)

var fromIp string
var toIp string
var portTo int32
var debug bool

func init() {
	startCmd.Flags().StringVar(&fromIp, "from", "", "Specifies which machine the communication is initiated from.")
	startCmd.Flags().StringVar(&toIp, "to", "", "Specifies which machine the communication is destined to go to.")
	startCmd.Flags().Int32Var(&portTo, "port", -1, "Specifies which port should be checked.")
	startCmd.Flags().BoolVar(&debug, "debug", false, "Specifies if debug messages should be emitted.")
	rootCmd.AddCommand(startCmd)
}

var startCmd = &cobra.Command{
	Use:   "run",
	Short: "run analysis",
	Run: func(cmd *cobra.Command, args []string) {

		if debug {
			log.SetLevel(log.DebugLevel)
		}

		cfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			log.Fatalf("unable to load SDK config, %v", err)
		}

		ipFrom := net.ParseIP(fromIp)
		ipTo := net.ParseIP(toIp)
		port := portTo
		fmt.Printf("checking if %s can reach %s\n", ipFrom.String(), ipTo.String())

		ec2Svc := ec2.NewFromConfig(cfg)
		ec2Instance, err := findEC2ByPrivateIp(ipFrom.String(), ec2Svc)
		if err != nil {
			log.Fatalf("%s", err)
		}

		securityGroups, err := getSecurityGroupsById(ec2Instance, err, ec2Svc)
		if err != nil {
			log.Fatalf("%s", err)
		}

		tml.Printf("<yellow>%s</yellow>\n", *ec2Instance.VpcId)

		//TODO: if len security groups <-0 then just fail straight away
		securityGroup := (*securityGroups)[0]

		canEscapeEc2 := checkIfSecurityGroupAllowsEgressForIPandPort(securityGroup, port, ipTo)
		if canEscapeEc2 {
			tml.Printf("<green>✓</green> ec2 -> %s\n", *securityGroup.GroupId)
		} else {
			tml.Println("<red>×</red> ec2")
		}

		//TODO: but here we can escape through private or public internet
		//if private we need to check if its the same VPC
		//if its diff vpc we need to check if peering is active
		//it might also go through TGW
		canEscapeSubnet, route := lookForRouteOutsideSubnet(ec2Instance, ec2Svc, ipTo)

		if canEscapeSubnet {
			tml.Printf("<green>✓</green> subnet '%s' -> route opened '%s'\n", *ec2Instance.SubnetId, *route.DestinationCidrBlock)
		} else {
			tml.Println("<red>×</red> subnet - route table")
		}

		if route.VpcPeeringConnectionId != nil {
			vpcQuery := &ec2.DescribeVpcPeeringConnectionsInput{
				VpcPeeringConnectionIds: []string{*route.VpcPeeringConnectionId},
			}

			vpcs, err := ec2Svc.DescribeVpcPeeringConnections(context.Background(), vpcQuery)

			if err != nil {
				log.Fatalf("cant find vpc peering connections - %s", err)
			}

			//TODO: more than one vpc
			vpcPeeringStatus := vpcs.VpcPeeringConnections[0].Status
			if vpcPeeringStatus.Code == types.VpcPeeringConnectionStateReasonCodeActive {
				tml.Println("<green>✓</green> vpc peering active")
			} else {
				tml.Printf("<red>×</red> vpc peering status - %s - %s\n", vpcPeeringStatus.Code, *vpcPeeringStatus.Message)
			}
		}

		//TODO: attacehements if there is no attacehement then there is no connection
		if route.TransitGatewayId != nil {
			tgwQuery := &ec2.DescribeTransitGatewaysInput{
				TransitGatewayIds: []string{*route.TransitGatewayId},
			}

			tgws, err := ec2Svc.DescribeTransitGateways(context.Background(), tgwQuery)

			if err != nil {
				log.Fatalf("cant find vpc peering connections - %s", err)
			}

			//TODO: more than one vpc
			tgwState := tgws.TransitGateways[0].State
			if tgwState == types.TransitGatewayStateAvailable {
				tml.Println("<green>✓</green> tgw available")
			} else {
				tml.Printf("<red>×</red> tgw unavailable - %s\n", tgwState)
			}
		}

		ec2InstanceTo, err := findEC2ByPrivateIp(ipTo.String(), ec2Svc)
		if err != nil {
			log.Fatalf("%s", err)
		}

		tml.Printf("<yellow>%s</yellow>\n", *ec2InstanceTo.VpcId)
		securityGroupsTo, err := getSecurityGroupsById(ec2InstanceTo, err, ec2Svc)
		if err != nil {
			log.Fatalf("%s", err)
		}

		securityGroupTo := (*securityGroupsTo)[0]
		canEnterEc2 := checkIfSecurityGroupAllowsIngressForIPandPort(securityGroupTo, port, ipFrom)
		if canEnterEc2 {
			tml.Printf("<green>✓</green> -> ec2 %s\n", *securityGroup.GroupId)
		} else {
			tml.Println("<red>×</red> -> ec2")
		}
	},
}

//TODO: proper error handling
func lookForRouteOutsideSubnet(ec2Instance *types.Instance, ec2Svc *ec2.Client, ipTo net.IP) (bool, *types.Route) {
	log.Debug("Checking subnet routing table")
	foundRoutingTable := false
	filterSubnetId := "association.subnet-id"
	routeTableQuery := &ec2.DescribeRouteTablesInput{
		Filters: []types.Filter{
			{
				Name:   &filterSubnetId,
				Values: []string{*ec2Instance.SubnetId},
			},
		},
	}

	routeTables, _ := ec2Svc.DescribeRouteTables(context.Background(), routeTableQuery)
	//TODO: handle many route tables
	routeTable := routeTables.RouteTables[0]
	var route types.Route

	for _, r := range routeTable.Routes {
		//TODO: check why dest cidr block can be nil
		if r.DestinationCidrBlock != nil {
			//TODO: ignore for now igw and 0.0.0.0/0
			if (*r.DestinationCidrBlock) == "0.0.0.0/0" {
				continue
			}

			_, cidr, err := net.ParseCIDR(*r.DestinationCidrBlock)
			if err != nil {
				log.Fatalf("%s", err)
			}

			if cidr.Contains(ipTo) {
				foundRoutingTable = true
				route = r
			}
		}
	}
	return foundRoutingTable, &route
}

//TODO: return err and add in proper error handling
func checkIfSecurityGroupAllowsIngressForIPandPort(securityGroup types.SecurityGroup, port int32, ipFrom net.IP) bool {
	canEnterEc2 := false
	log.Debug("Checking security group egress")
	//TODO: todo if port not specified create a list of ports that would be able to be sent through
	for _, ingress := range securityGroup.IpPermissions {
		//log.Debugf("checking ingress rule %s", ToStringIpPermission(egress))
		//TODO: check if required port qualifies for this entry
		if ingress.FromPort >= port && port <= ingress.ToPort {
			//TODO: this can be security group or a single ip not always cidr
			for _, ipRange := range ingress.IpRanges {
				_, cidr, err := net.ParseCIDR(*ipRange.CidrIp)
				if err != nil {
					log.Fatalf("%s", err)
				}

				if cidr.Contains(ipFrom) {
					canEnterEc2 = true
				}
			}
		}
	}
	return canEnterEc2
}

//TODO: return err and add in proper error handling
func checkIfSecurityGroupAllowsEgressForIPandPort(securityGroup types.SecurityGroup, port int32, ipTo net.IP) bool {
	canEscapeEc2 := false
	log.Debug("Checking security group egress")
	//TODO: todo if port not specified create a list of ports that would be able to be sent through
	for _, egress := range securityGroup.IpPermissionsEgress {
		//log.Debugf("checking ingress rule %s", ToStringIpPermission(egress))
		//TODO: check if required port qualifies for this entry
		if egress.FromPort >= port && port <= egress.ToPort {
			//TODO: this can be security group or a single ip not always cidr
			for _, ipRange := range egress.IpRanges {
				_, cidr, err := net.ParseCIDR(*ipRange.CidrIp)
				if err != nil {
					log.Fatalf("%s", err)
				}

				if cidr.Contains(ipTo) {
					canEscapeEc2 = true
				}
			}
		}
	}
	return canEscapeEc2
}

func getSecurityGroupsById(ec2Instance *types.Instance, err error, ec2Svc *ec2.Client) (*[]types.SecurityGroup, error) {
	//TODO: consider multiple security groups
	//TODO: if cidr range points at security group you need to check this security group
	// and which instances it has - does it match the one we are looking to find
	groupId := ec2Instance.SecurityGroups[0].GroupId

	securityGroupQuery := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{*groupId},
	}
	log.Debug("looking for security group")
	securityGroupsResult, err := ec2Svc.DescribeSecurityGroups(context.Background(), securityGroupQuery)
	if err != nil {
		return &[]types.SecurityGroup{}, nil
	}
	return &securityGroupsResult.SecurityGroups, nil
}

func ToStringIpPermission(ip types.IpPermission) string {
	return fmt.Sprintf("%s %d-%d", *ip.IpProtocol, ip.FromPort, ip.ToPort)
}

func findEC2ByPrivateIp(privateIp string, client *ec2.Client) (*types.Instance, error) {
	log.Debugf("Looking for EC2 with private ip: '%s'", privateIp)
	filterName := "network-interface.addresses.private-ip-address"
	query := &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name:   &filterName,
				Values: []string{privateIp},
			},
		},
	}

	ec2result, err := client.DescribeInstances(context.Background(), query)

	if err != nil {
		return &types.Instance{}, fmt.Errorf("error when looking for ec2 %s", err)
	}

	//TODO: what if we get more reservations or isntances?
	return &ec2result.Reservations[0].Instances[0], nil
}
