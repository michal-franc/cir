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

type Check struct {
	IsPassing bool
	Reason    string
}

type Analysis struct {
	CanTheyConnect                bool
	CanEscapeSource               *Check
	CanEnterDestination           *Check
	SourceSubnetHasRoute          *Check
	DestinationSubnetHasRoute     *Check
	AreInTheSameVpc               bool
	ConnectionBetweenVPCsIsValid  *Check
	ConnectionBetweenVPCsIsActive *Check
}

func toStringIpPermission(ip types.IpPermission) string {
	return fmt.Sprintf("%s %d-%d", *ip.IpProtocol, ip.FromPort, ip.ToPort)
}

func RunAnalysis(data scanner.AwsData, client *ec2.Client, port int32) (*Analysis, error) {
	ipDestination := net.ParseIP(data.Destination.PrivateIp)
	ipSource := net.ParseIP(data.Source.PrivateIp)
	analysis := &Analysis{}
	analysis.CanEscapeSource = checkIfSecurityGroupAllowsEgressForIPandPort(data.Source.SecurityGroup, *data.Destination.SecurityGroup.GroupId, port, ipDestination)

	canEscapeSourceSubnet, routeSource := lookForRouteOutsideSubnet(&data.Source.RouteTable, ipDestination)
	analysis.SourceSubnetHasRoute = canEscapeSourceSubnet

	analysis.CanEnterDestination = checkIfSecurityGroupAllowsIngressForIPandPort(data.Destination.SecurityGroup, *data.Source.SecurityGroup.GroupId, port, ipSource)

	canEscapeDestinationSubnet, routeDestination := lookForRouteOutsideSubnet(&data.Source.RouteTable, ipDestination)
	analysis.DestinationSubnetHasRoute = canEscapeDestinationSubnet

	analysis.AreInTheSameVpc = data.Destination.VpcId == data.Source.VpcId

	if !analysis.AreInTheSameVpc {
		analysis.ConnectionBetweenVPCsIsValid = checkIfVPCConnectionValid(routeSource, routeDestination)
		if analysis.ConnectionBetweenVPCsIsValid.IsPassing {
			analysis.ConnectionBetweenVPCsIsActive = checkIfVPCConnectionIsActive(routeSource, client)
		}
	}

	return analysis, nil
}

//TODO: error handling instead of fatals
func checkIfVPCConnectionIsActive(routeSource *types.Route, client *ec2.Client) *Check {
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
			return &Check{
				IsPassing: true,
				Reason:    fmt.Sprintf("vpc peering - %s - is active", *vpcs.VpcPeeringConnections[0].VpcPeeringConnectionId),
			}
		} else {
			return &Check{
				IsPassing: false,
				Reason:    fmt.Sprintf("vpc peering - %s - is inactive", *vpcs.VpcPeeringConnections[0].VpcPeeringConnectionId),
			}
		}
	}

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
			return &Check{
				IsPassing: true,
				Reason:    fmt.Sprintf("tgw - %s - is available", *tgws.TransitGateways[0].TransitGatewayId),
			}
		} else {
			return &Check{
				IsPassing: false,
				Reason:    fmt.Sprintf("tgw - %s - is unavailable", *tgws.TransitGateways[0].TransitGatewayId),
			}
		}
	}

	return &Check{
		IsPassing: false,
		Reason:    "unsupported vpc connection type",
	}
}

func checkIfVPCConnectionValid(sourceRoute *types.Route, destRoute *types.Route) *Check {
	if sourceRoute.CarrierGatewayId != nil || destRoute.CarrierGatewayId != nil {
		log.Warn("route check: CarrierGateway not supported yet")
		return &Check{false, "CarrierGateway not supported yet"}
	}

	if sourceRoute.EgressOnlyInternetGatewayId != nil || destRoute.EgressOnlyInternetGatewayId != nil {
		log.Warn("route check: EgressOnlyIG not supported yet")
		return &Check{false, "EgressOnlyIG not supported yet"}
	}

	if sourceRoute.GatewayId != nil || destRoute.GatewayId != nil {
		log.Warn("route check: Gateway not supported yet")
		return &Check{false, "Gateway not supported yet"}
	}

	if sourceRoute.LocalGatewayId != nil || destRoute.LocalGatewayId != nil {
		log.Warn("route check: LocalGateway not supported yet")
		return &Check{false, "LocalGateway not supported yet"}
	}

	if sourceRoute.NatGatewayId != nil || destRoute.NatGatewayId != nil {
		log.Warn("route check: NatGateway not supported yet")
		return &Check{false, "NatGateway not supported yet"}
	}

	if sourceRoute.NetworkInterfaceId != nil || destRoute.NetworkInterfaceId != nil {
		log.Warn("route check: ENI not supported yet")
		return &Check{false, "Eni not supported yet"}
	}

	if sourceRoute.VpcPeeringConnectionId != nil && destRoute.VpcPeeringConnectionId != nil {
		if sourceRoute.VpcPeeringConnectionId != destRoute.VpcPeeringConnectionId {
			return &Check{false, fmt.Sprintf("source vpc peering id: %s - doesnt match - dest vpc peering id: %s", *sourceRoute.VpcPeeringConnectionId, *destRoute.VpcPeeringConnectionId)}
		}
		return &Check{true, fmt.Sprintf("source and dest connected using vpc peering: %s", *sourceRoute.VpcPeeringConnectionId)}
	}

	if sourceRoute.TransitGatewayId != nil && destRoute.TransitGatewayId != nil {
		if sourceRoute.TransitGatewayId != destRoute.TransitGatewayId {
			return &Check{false, fmt.Sprintf("source tgw id: %s - doesnt match - dest tgw id: %s", *sourceRoute.TransitGatewayId, *destRoute.TransitGatewayId)}
		}
		return &Check{true, fmt.Sprintf("source and dest connected using tgw: %s", *sourceRoute.TransitGatewayId)}
	}

	return &Check{false, "not compatible or supported vpc connection"}
}

//TODO: proper error handling
//TODO: ipv6 support
func lookForRouteOutsideSubnet(routeTable *types.RouteTable, ipDestination net.IP) (*Check, *types.Route) {
	log.Debug("Checking subnet routing table")
	for _, r := range routeTable.Routes {
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
				return &Check{
					IsPassing: true,
					Reason:    fmt.Sprintf("found route in route table '%s' with range '%s'", *routeTable.RouteTableId, *r.DestinationCidrBlock),
				}, &r
			}
		}
	}
	return &Check{
		IsPassing: false,
		Reason:    "no route found in routing table allowing traffic",
	}, nil
}

//TODO: return err and add in proper error handling
func checkIfSecurityGroupAllowsIngressForIPandPort(securityGroupTo types.SecurityGroup, securityGroupFromId string, port int32, ipFrom net.IP) *Check {
	log.Debugf("Checking security group ingress - %s\n", *securityGroupTo.GroupId)
	for _, ingress := range securityGroupTo.IpPermissions {
		if port >= ingress.FromPort && port <= ingress.ToPort {
			log.Debugf("found port opening %s", toStringIpPermission(ingress))
			if len(ingress.Ipv6Ranges) > 0 {
				return &Check{
					IsPassing: false,
					Reason:    "IPV6 is not supported yet",
				}
			}

			if len(ingress.PrefixListIds) > 0 {
				return &Check{
					IsPassing: false,
					Reason:    "PrefixListIds are not supported yet",
				}
			}
			// User ids cover sestinations like security group
			log.Debugf("user ids %d", len(ingress.UserIdGroupPairs))
			if len(ingress.UserIdGroupPairs) > 0 {
				for _, userIdGroup := range ingress.UserIdGroupPairs {
					log.Debugf("group id %s", *userIdGroup.GroupId)
					// check if this group id is security group
					if strings.HasPrefix(*userIdGroup.GroupId, "sg-") {
						if strings.EqualFold(*userIdGroup.GroupId, securityGroupFromId) {
							return &Check{
								IsPassing: true,
								Reason:    fmt.Sprintf("found inbound rule pointing tu security group - %s", *userIdGroup.GroupId),
							}
						}
					} else {
						return &Check{
							IsPassing: false,
							Reason:    fmt.Sprintf("this source is not supported yet - userIdGroup %s", *userIdGroup.GroupId),
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
					return &Check{
						IsPassing: true,
						Reason:    fmt.Sprintf("found inbound rule pointing at ipv4 cidr range %s", *ipRange.CidrIp),
					}
				}
			}
		}
	}
	return &Check{
		IsPassing: false,
		Reason:    "security groups is not allowing this traffic",
	}
}

//TODO: return err and add in proper error handling
func checkIfSecurityGroupAllowsEgressForIPandPort(securityGroupFrom types.SecurityGroup, securityGroupToId string, port int32, ipDestination net.IP) *Check {
	log.Debugf("Checking security group egress - %s\n", *securityGroupFrom.GroupId)
	for _, egress := range securityGroupFrom.IpPermissionsEgress {
		if port >= egress.FromPort && port <= egress.ToPort {
			log.Debugf("found port opening %s", toStringIpPermission(egress))
			if len(egress.Ipv6Ranges) > 0 {
				return &Check{
					IsPassing: false,
					Reason:    "IPV6 is not supported yet",
				}
			}

			if len(egress.PrefixListIds) > 0 {
				return &Check{
					IsPassing: false,
					Reason:    "PrefixListIds are not supported yet",
				}
			}

			// User ids cover sestinations like security group
			log.Debugf("user ids %d", len(egress.UserIdGroupPairs))
			if len(egress.UserIdGroupPairs) > 0 {
				for _, userIdGroup := range egress.UserIdGroupPairs {
					log.Debugf("group id %s", *userIdGroup.GroupId)
					// check if this group id is security group
					if strings.HasPrefix(*userIdGroup.GroupId, "sg-") {
						if strings.EqualFold(*userIdGroup.GroupId, securityGroupToId) {
							return &Check{
								IsPassing: true,
								Reason:    fmt.Sprintf("found outbound rule pointing tu security group - %s", *userIdGroup.GroupId),
							}
						}
					} else {
						return &Check{
							IsPassing: false,
							Reason:    fmt.Sprintf("this destination is not supported yet - userIdGroup %s", *userIdGroup.GroupId),
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

				if cidr.Contains(ipDestination) {
					return &Check{
						IsPassing: true,
						Reason:    fmt.Sprintf("found outbound rule pointing at ipv4 cidr range %s", *ipRange.CidrIp),
					}
				}
			}
		}
	}

	return &Check{
		IsPassing: false,
		Reason:    "security groups is not allowing this traffic",
	}
}
