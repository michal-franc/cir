package scanner

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	log "github.com/sirupsen/logrus"
)

// ResourceNetworkMetaData - main struct for single aws resource network metadata
type ResourceNetworkMetaData struct {
	PrivateIP     string
	VpcID         string
	SecurityGroup types.SecurityGroup
	SubnetID      string
	RouteTable    types.RouteTable
}

// AwsData - main struct holding scanned resources for further processing
type AwsData struct {
	Source      *ResourceNetworkMetaData
	Destination *ResourceNetworkMetaData
}

// ScanAwsEc2 - initiates ec2 aws scan
func ScanAwsEc2(client *ec2.Client, sourceIP string, destinationIP string) (*AwsData, error) {
	ec2InstanceSource, err := findEC2ByPrivateIP(sourceIP, client)
	if err != nil {
		return &AwsData{}, err
	}

	ec2InstanceDestination, err := findEC2ByPrivateIP(destinationIP, client)
	if err != nil {
		return &AwsData{}, err
	}

	securityGroupsDestination, err := getSecurityGroupsByID(ec2InstanceDestination, client)
	if err != nil {
		return &AwsData{}, err
	}

	securityGroupsSource, err := getSecurityGroupsByID(ec2InstanceSource, client)
	if err != nil {
		return &AwsData{}, err
	}

	routeTableSource, err := getRouteTablesForEc2(ec2InstanceSource, client)
	if err != nil {
		return &AwsData{}, err
	}

	routeTableDestination, err := getRouteTablesForEc2(ec2InstanceDestination, client)
	if err != nil {
		return &AwsData{}, err
	}

	return &AwsData{
		Source: &ResourceNetworkMetaData{
			PrivateIP:     *ec2InstanceSource.PrivateIpAddress,
			SecurityGroup: (*securityGroupsSource)[0],
			VpcID:         *ec2InstanceSource.VpcId,
			SubnetID:      *ec2InstanceSource.SubnetId,
			RouteTable:    *routeTableSource,
		},
		Destination: &ResourceNetworkMetaData{
			PrivateIP:     *ec2InstanceDestination.PrivateIpAddress,
			SecurityGroup: (*securityGroupsDestination)[0],
			VpcID:         *ec2InstanceDestination.VpcId,
			SubnetID:      *ec2InstanceDestination.SubnetId,
			RouteTable:    *routeTableDestination,
		},
	}, nil
}

func findEC2ByPrivateIP(privateIP string, client *ec2.Client) (*types.Instance, error) {
	log.Debugf("Looking for EC2 with private ip: '%s'", privateIP)
	filterName := "network-interface.addresses.private-ip-address"
	query := &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name:   &filterName,
				Values: []string{privateIP},
			},
		},
	}

	ec2result, err := client.DescribeInstances(context.Background(), query)

	if err != nil {
		return &types.Instance{}, fmt.Errorf("error when looking for ec2 %s", err)
	}

	if len(ec2result.Reservations) > 1 {
		return nil, fmt.Errorf("multiple reservations not supported")
	}

	if len(ec2result.Reservations) <= 0 {
		return nil, fmt.Errorf("ec2 with ip '%s' not found", privateIP)
	}
	if len(ec2result.Reservations[0].Instances) <= 0 {
		return nil, fmt.Errorf("ec2 with ip '%s' not found", privateIP)
	}

	if len(ec2result.Reservations[0].Instances) > 1 {
		return nil, fmt.Errorf("multiple ec2 found for given ip '%s'", privateIP)
	}

	return &ec2result.Reservations[0].Instances[0], nil
}

func getSecurityGroupsByID(ec2Instance *types.Instance, ec2Svc *ec2.Client) (*[]types.SecurityGroup, error) {
	groupID := ec2Instance.SecurityGroups[0].GroupId

	securityGroupQuery := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{*groupID},
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

func getRouteTablesForEc2(ec2Instance *types.Instance, ec2Svc *ec2.Client) (*types.RouteTable, error) {
	log.Debug("Checking subnet routing table")
	filterSubnetID := "association.subnet-id"
	routeTableQuery := &ec2.DescribeRouteTablesInput{
		Filters: []types.Filter{
			{
				Name:   &filterSubnetID,
				Values: []string{*ec2Instance.SubnetId},
			},
		},
	}

	routeTables, _ := ec2Svc.DescribeRouteTables(context.Background(), routeTableQuery)

	if len(routeTables.RouteTables) <= 0 {
		return nil, fmt.Errorf("no route table found for ec2 with ip '%s'", *ec2Instance.PrivateIpAddress)
	}
	return &routeTables.RouteTables[0], nil
}
