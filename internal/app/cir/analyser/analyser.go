package analyser

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/michal-franc/cir/internal/app/cir/scanner"
	log "github.com/sirupsen/logrus"
	"net"
	"strings"
)

type Analysis struct {
	//TODO: single quick response for non verbose display
	CanTheyConnect                     bool
	CanEscapeSource                    bool
	CanEnterDestination                bool
	SourceSubnetHasRoute               bool
	DestinationSubnetHasRoute          bool
	AreInTheSameVpc                    bool
	ConnectionBetweenVPCsIsValid       bool
	ConnectionBetweenVPCsIsValidReason string
	ConnectionBetweenVPCsIsActive      bool
}

func toStringIpPermission(ip types.IpPermission) string {
	return fmt.Sprintf("%s %d-%d", *ip.IpProtocol, ip.FromPort, ip.ToPort)
}

func RunAnalysis(data scanner.AwsData, client *ec2.Client, port int32) (*Analysis, error) {
	ipDestination := net.ParseIP(data.Destination.PrivateIp)
	ipSource := net.ParseIP(data.Source.PrivateIp)
	analysis := &Analysis{}
	canEscapeSource := checkIfSecurityGroupAllowsEgressForIPandPort(data.Source.SecurityGroup, *data.Destination.SecurityGroup.GroupId, port, ipDestination)
	analysis.CanEscapeSource = canEscapeSource

	//TODO: but here we can escape through private or public internet
	//if private we need to check if its the same VPC
	//if its diff vpc we need to check if peering is active
	//it might also go through TGW
	canEscapeSourceSubnet, routeSource := lookForRouteOutsideSubnet(&data.Source.RouteTable, ipDestination)
	analysis.SourceSubnetHasRoute = canEscapeSourceSubnet

	canEnterDestination := checkIfSecurityGroupAllowsIngressForIPandPort(data.Destination.SecurityGroup, *data.Source.SecurityGroup.GroupId, port, ipSource)
	analysis.CanEnterDestination = canEnterDestination

	canEscapeDestinationSubnet, routeDestination := lookForRouteOutsideSubnet(&data.Source.RouteTable, ipDestination)
	analysis.DestinationSubnetHasRoute = canEscapeDestinationSubnet

	analysis.AreInTheSameVpc = data.Destination.VpcId == data.Source.VpcId

	if !analysis.AreInTheSameVpc {
		valid, reason := checkIfVPCConnectionValid(routeSource, routeDestination)
		analysis.ConnectionBetweenVPCsIsValid = valid
		analysis.ConnectionBetweenVPCsIsValidReason = reason
		if valid {
			analysis.ConnectionBetweenVPCsIsActive = checkIfVPCConnectionIsActive(routeSource, client)
		}
	}

	return analysis, nil
}

//TODO: error handling instead of fatals
//TODO: reason
func checkIfVPCConnectionIsActive(routeSource *types.Route, client *ec2.Client) bool {
	if routeSource.VpcPeeringConnectionId != nil {
		vpcQuery := &ec2.DescribeVpcPeeringConnectionsInput{
			VpcPeeringConnectionIds: []string{*routeSource.VpcPeeringConnectionId},
		}

		vpcs, err := client.DescribeVpcPeeringConnections(context.Background(), vpcQuery)

		if err != nil {
			log.Fatalf("cant find vpc peering connections - %s", err)
		}

		//TODO: more than one vpc
		vpcPeeringStatus := vpcs.VpcPeeringConnections[0].Status
		if vpcPeeringStatus.Code == types.VpcPeeringConnectionStateReasonCodeActive {
			return true
		}
	}

	//TODO: attacehements if there is no attacehement then there is no connection
	if routeSource.TransitGatewayId != nil {
		tgwQuery := &ec2.DescribeTransitGatewaysInput{
			TransitGatewayIds: []string{*routeSource.TransitGatewayId},
		}

		tgws, err := client.DescribeTransitGateways(context.Background(), tgwQuery)

		if err != nil {
			log.Fatalf("cant find vpc peering connections - %s", err)
		}

		//TODO: more than one vpc
		tgwState := tgws.TransitGateways[0].State
		if tgwState == types.TransitGatewayStateAvailable {
			return true
		}
	}

	return false
}

func checkIfVPCConnectionValid(sourceRoute *types.Route, destRoute *types.Route) (bool, string) {
	if sourceRoute.CarrierGatewayId != nil || destRoute.CarrierGatewayId != nil {
		log.Warn("route check: CarrierGateway not supported yet")
		return false, "CarrierGateway not supported yet"
	}

	if sourceRoute.EgressOnlyInternetGatewayId != nil || destRoute.EgressOnlyInternetGatewayId != nil {
		log.Warn("route check: EgressOnlyIG not supported yet")
		return false, "EgressOnlyIG not supported yet"
	}

	if sourceRoute.GatewayId != nil || destRoute.GatewayId != nil {
		log.Warn("route check: Gateway not supported yet")
		return false, "Gateway not supported yet"
	}

	if sourceRoute.LocalGatewayId != nil || destRoute.LocalGatewayId != nil {
		log.Warn("route check: LocalGateway not supported yet")
		return false, "LocalGateway not supported yet"
	}

	if sourceRoute.NatGatewayId != nil || destRoute.NatGatewayId != nil {
		log.Warn("route check: NatGateway not supported yet")
		return false, "NatGateway not supported yet"
	}

	if sourceRoute.NetworkInterfaceId != nil || destRoute.NetworkInterfaceId != nil {
		log.Warn("route check: ENI not supported yet")
		return false, "Eni not supported yet"
	}

	if sourceRoute.VpcPeeringConnectionId != nil && destRoute.VpcPeeringConnectionId != nil {
		if sourceRoute.VpcPeeringConnectionId != destRoute.VpcPeeringConnectionId {
			return false, fmt.Sprintf("source vpc peering id: %s - doesnt match - dest vpc peering id: %s", *sourceRoute.VpcPeeringConnectionId, *destRoute.VpcPeeringConnectionId)
		}
		return true, fmt.Sprintf("source and dest connected using vpc peering: %s", *sourceRoute.VpcPeeringConnectionId)
	}

	if sourceRoute.TransitGatewayId != nil && destRoute.TransitGatewayId != nil {
		if sourceRoute.TransitGatewayId != destRoute.TransitGatewayId {
			return false, fmt.Sprintf("source tgw id: %s - doesnt match - dest tgw id: %s", *sourceRoute.TransitGatewayId, *destRoute.TransitGatewayId)
		}
		return true, fmt.Sprintf("source and dest connected using tgw: %s", *sourceRoute.TransitGatewayId)
	}

	return false, "not compatible or supported vpc connection"
}

//TODO: proper error handling
func lookForRouteOutsideSubnet(routeTable *types.RouteTable, ipDestination net.IP) (bool, *types.Route) {
	log.Debug("Checking subnet routing table")
	foundRoutingTable := false
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

			if cidr.Contains(ipDestination) {
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
	//TODO: check ip protocol udp vs tcp
	//TODO: todo if port not specified create a list of ports that would be able to be sent through
	for _, ingress := range securityGroupTo.IpPermissions {
		if port >= ingress.FromPort && port <= ingress.ToPort {
			log.Debugf("found port opening %s", toStringIpPermission(ingress))
			if len(ingress.Ipv6Ranges) > 0 {
				log.Warn("IPV6 is not supported yet.")
			}

			if len(ingress.PrefixListIds) > 0 {
				log.Warn("Prefixes are not supported yet.")
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
					} else {
						log.Warnf("security group userIDgroup not supported - %s", *userIdGroup.GroupId)
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
func checkIfSecurityGroupAllowsEgressForIPandPort(securityGroupFrom types.SecurityGroup, securityGroupToId string, port int32, ipDestination net.IP) bool {
	canEscapeEc2 := false
	log.Debugf("Checking security group egress - %s\n", *securityGroupFrom.GroupId)
	//TODO: check ip protocol udp vs tcp
	//TODO: todo if port not specified create a list of ports that would be able to be sent through
	for _, egress := range securityGroupFrom.IpPermissionsEgress {
		if port >= egress.FromPort && port <= egress.ToPort {
			log.Debugf("found port opening %s", toStringIpPermission(egress))
			if len(egress.Ipv6Ranges) > 0 {
				log.Warn("IPV6 is not supported yet.")
			}

			if len(egress.PrefixListIds) > 0 {
				log.Warn("Prefixes are not supported yet.")
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
					} else {
						log.Warnf("security group userIDgroup not supported - %s", *userIdGroup.GroupId)
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

				if cidr.Contains(ipDestination) {
					canEscapeEc2 = true
				}
			}
		}
	}
	return canEscapeEc2
}
