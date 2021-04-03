package commands

import (
	"github.com/spf13/cobra"
	"strings"

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
var port int32
var debug bool

func init() {
	startCmd.Flags().StringVar(&fromIp, "from", "", "Specifies which machine the communication is initiated from.")
	startCmd.Flags().StringVar(&toIp, "to", "", "Specifies which machine the communication is destined to go to.")
	startCmd.Flags().Int32Var(&port, "port", -1, "Specifies which port should be checked.")
	startCmd.Flags().BoolVar(&debug, "debug", false, "Specifies if debug messages should be emitted.")
	rootCmd.AddCommand(startCmd)
}

var startCmd = &cobra.Command{
	Use:   "run",
	Short: "run analysis",
	Run: func(cmd *cobra.Command, args []string) {
		log.SetLevel(log.WarnLevel)

		if debug {
			log.SetLevel(log.DebugLevel)
		}

		cfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			log.Fatalf("unable to load SDK config, %v", err)
		}

		ipFrom := net.ParseIP(fromIp)
		ipTo := net.ParseIP(toIp)
		fmt.Printf("checking if '%s' can reach '%s on port '%d'\n", ipFrom.String(), ipTo.String(), port)

		ec2Svc := ec2.NewFromConfig(cfg)
		ec2InstanceFrom, err := findEC2ByPrivateIp(ipFrom.String(), ec2Svc)
		if err != nil {
			log.Fatalf("%s", err)
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

		securityGroupsFrom, err := getSecurityGroupsById(ec2InstanceFrom, err, ec2Svc)
		if err != nil {
			log.Fatalf("%s", err)
		}

		tml.Printf("<yellow>%s</yellow>\n", *ec2InstanceFrom.VpcId)

		//TODO: if len security groups <-0 then just fail straight away
		securityGroupFrom := (*securityGroupsFrom)[0]
		securityGroupTo := (*securityGroupsTo)[0]

		canEscapeEc2 := checkIfSecurityGroupAllowsEgressForIPandPort(securityGroupFrom, *securityGroupTo.GroupId, port, ipTo)
		if canEscapeEc2 {
			tml.Printf("<green>✓</green> ec2 -> %s\n", *securityGroupFrom.GroupId)
		} else {
			tml.Println("<red>×</red> ec2")
		}

		//TODO: but here we can escape through private or public internet
		//if private we need to check if its the same VPC
		//if its diff vpc we need to check if peering is active
		//it might also go through TGW
		canEscapeSubnet, route := lookForRouteOutsideSubnet(ec2InstanceFrom, ec2Svc, ipTo)

		if canEscapeSubnet {
			tml.Printf("<green>✓</green> subnet '%s' -> route opened '%s'\n", *ec2InstanceFrom.SubnetId, *route.DestinationCidrBlock)
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

		canEnterEc2 := checkIfSecurityGroupAllowsIngressForIPandPort(securityGroupTo, *securityGroupFrom.GroupId, port, ipFrom)
		if canEnterEc2 {
			tml.Printf("<green>✓</green> -> ec2 %s\n", *securityGroupFrom.GroupId)
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
func checkIfSecurityGroupAllowsIngressForIPandPort(securityGroupTo types.SecurityGroup, securityGroupFromId string, port int32, ipFrom net.IP) bool {
	canEnterEc2 := false
	log.Debugf("Checking security group ingress - %s\n", *securityGroupTo.GroupId)
	//TODO: todo if port not specified create a list of ports that would be able to be sent through
	for _, ingress := range securityGroupTo.IpPermissions {
		if port >= ingress.FromPort && port <= ingress.ToPort {
			log.Debugf("found port opening %s", ToStringIpPermission(ingress))
			if len(ingress.Ipv6Ranges) > 0 {
				log.Warn("IPV6 is not supported yet.")
			}

			if len(ingress.PrefixListIds) > 0 {
				log.Warn("Prefixes are not supported yet.")
			}

			if *ingress.IpProtocol != "" {
				log.Warn("IpProtocol is not supported yet.")
			}

			// User ids cover sestinations like security group
			log.Debugf("user ids %d", len(ingress.UserIdGroupPairs))
			if len(ingress.UserIdGroupPairs) > 0 {
				for _, userIdGroup := range ingress.UserIdGroupPairs {
					log.Debugf("group id %s", *userIdGroup.GroupId)
					// check if this group id is security group
					if strings.HasPrefix(*userIdGroup.GroupId, "sg-") {
						if strings.EqualFold(*userIdGroup.GroupId, securityGroupFromId) {
							return true
						}
					}
				}
			}

			// IP ranges cover only hardcoded cidr values
			log.Debugf("ipranges ipv4 %d", len(ingress.IpRanges))
			for _, ipRange := range ingress.IpRanges {
				log.Debugf("Checking if security group with '%s'\n", *ipRange.CidrIp)
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
func checkIfSecurityGroupAllowsEgressForIPandPort(securityGroupFrom types.SecurityGroup, securityGroupToId string, port int32, ipTo net.IP) bool {
	canEscapeEc2 := false
	log.Debugf("Checking security group egress - %s\n", *securityGroupFrom.GroupId)
	//TODO: todo if port not specified create a list of ports that would be able to be sent through
	for _, egress := range securityGroupFrom.IpPermissionsEgress {
		if port >= egress.FromPort && port <= egress.ToPort {
			log.Debugf("found port opening %s", ToStringIpPermission(egress))
			if len(egress.Ipv6Ranges) > 0 {
				log.Warn("IPV6 is not supported yet.")
			}

			if len(egress.PrefixListIds) > 0 {
				log.Warn("Prefixes are not supported yet.")
			}

			if *egress.IpProtocol != "" {
				log.Warn("IpProtocol is not supported yet.")
			}

			// User ids cover sestinations like security group
			log.Debugf("user ids %d", len(egress.UserIdGroupPairs))
			if len(egress.UserIdGroupPairs) > 0 {
				for _, userIdGroup := range egress.UserIdGroupPairs {
					log.Debugf("group id %s", *userIdGroup.GroupId)
					// check if this group id is security group
					if strings.HasPrefix(*userIdGroup.GroupId, "sg-") {
						if strings.EqualFold(*userIdGroup.GroupId, securityGroupToId) {
							return true
						}
					}
				}
			}

			// IP ranges cover only hardcoded cidr values
			log.Debugf("ipranges ipv4 %d", len(egress.IpRanges))
			for _, ipRange := range egress.IpRanges {
				log.Debugf("Checking if security group with '%s'\n", *ipRange.CidrIp)
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
	groupId := ec2Instance.SecurityGroups[0].GroupId

	securityGroupQuery := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{*groupId},
	}
	log.Debug("looking for security group")
	securityGroupsResult, err := ec2Svc.DescribeSecurityGroups(context.Background(), securityGroupQuery)
	if err != nil {
		return nil, err
	}

	if len(securityGroupsResult.SecurityGroups) <= 0 {
		return nil, fmt.Errorf("security group for ec2:%s not found", *ec2Instance.InstanceId)
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
	if len(ec2result.Reservations) <= 0 {
		return nil, fmt.Errorf("ec2 with ip '%s' not found", privateIp)
	}
	if len(ec2result.Reservations[0].Instances) <= 0 {
		return nil, fmt.Errorf("ec2 with ip '%s' not found", privateIp)
	}

	if len(ec2result.Reservations[0].Instances) >= 1 {
		return nil, fmt.Errorf("multiple ec2 found for given ip '%s'", privateIp)
	}

	return &ec2result.Reservations[0].Instances[0], nil
}
