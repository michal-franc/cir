package scanner

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	log "github.com/sirupsen/logrus"
	"strings"
)

// ResourceNetworkMetaData - main struct for single aws resource network metadata
type ResourceNetworkMetaData struct {
	ID            string
	PrivateIP     string
	VpcID         string
	SecurityGroup types.SecurityGroup
	SubnetID      string
	RouteTable    types.RouteTable
}

// AwsData - main struct holding scanned resources for further processing
type AwsData struct {
	Sources      []ResourceNetworkMetaData
	Destinations []ResourceNetworkMetaData
}

// ScanAwsEc2 - initiates ec2 aws scan
func ScanAwsEc2(client *ec2.Client, sourceQuery string, destinationQuery string) (*AwsData, error) {
	ec2InstancesSource, err := findEC2s(sourceQuery, client)
	log.Debugf("Found %d source instances\n", len(ec2InstancesSource))
	if err != nil {
		return nil, err
	}

	ec2InstancesDestination, err := findEC2s(destinationQuery, client)
	log.Debugf("Found %d destination instances\n", len(ec2InstancesSource))
	if err != nil {
		return nil, err
	}

	awsData := AwsData{
		Sources:      []ResourceNetworkMetaData{},
		Destinations: []ResourceNetworkMetaData{},
	}

	for _, ec2Instance := range ec2InstancesSource {
		metaDataInstance := ResourceNetworkMetaData{
			ID:        *ec2Instance.InstanceId,
			PrivateIP: *ec2Instance.PrivateIpAddress,
			VpcID:     *ec2Instance.VpcId,
			SubnetID:  *ec2Instance.SubnetId,
		}

		securityGroup, err := getSecurityGroupsByID(ec2Instance, client)
		if err != nil {
			return nil, err
		}
		metaDataInstance.SecurityGroup = securityGroup

		routeTable, err := getRouteTablesForEc2(ec2Instance, client)
		if err != nil {
			return nil, err
		}
		metaDataInstance.RouteTable = routeTable

		awsData.Sources = append(awsData.Sources, metaDataInstance)
	}

	for _, ec2Instance := range ec2InstancesDestination {
		metaDataInstance := ResourceNetworkMetaData{
			ID:        *ec2Instance.InstanceId,
			PrivateIP: *ec2Instance.PrivateIpAddress,
			VpcID:     *ec2Instance.VpcId,
			SubnetID:  *ec2Instance.SubnetId,
		}

		securityGroup, err := getSecurityGroupsByID(ec2Instance, client)
		if err != nil {
			return nil, err
		}
		metaDataInstance.SecurityGroup = securityGroup

		routeTable, err := getRouteTablesForEc2(ec2Instance, client)
		if err != nil {
			return nil, err
		}
		metaDataInstance.RouteTable = routeTable

		awsData.Destinations = append(awsData.Destinations, metaDataInstance)
	}

	return &awsData, nil
}

func findEC2s(query string, client *ec2.Client) ([]types.Instance, error) {
	log.Debugf("Looking for EC2 with query: '%s'", query)
	var filterName string
	var filterValue string
	if strings.Contains(query, "ip:") {
		filterName = "network-interface.addresses.private-ip-address"
		filterValue = query[3:]
	} else if strings.Contains(query, "name:") {
		filterName = "tag:Name"
		filterValue = query[5:]
	} else {
		return nil, fmt.Errorf("query %s not supported", query)
	}
	queryEc2 := &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name:   &filterName,
				Values: []string{filterValue},
			},
		},
	}

	ec2result, err := client.DescribeInstances(context.Background(), queryEc2)

	if err != nil {
		return nil, fmt.Errorf("error when looking for ec2 %s", err)
	}

	if len(ec2result.Reservations) <= 0 {
		return nil, fmt.Errorf("ec2 with query '%s' not found", query)
	}
	if len(ec2result.Reservations[0].Instances) <= 0 {
		return nil, fmt.Errorf("ec2 with query '%s' not found", query)
	}

	instances := &[]types.Instance{}

	for _, reservation := range ec2result.Reservations {
		for _, instance := range reservation.Instances {
			*instances = append(*instances, instance)
		}
	}

	return *instances, nil
}

func getSecurityGroupsByID(ec2Instance types.Instance, ec2Svc *ec2.Client) (types.SecurityGroup, error) {
	groupID := ec2Instance.SecurityGroups[0].GroupId

	securityGroupQuery := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{*groupID},
	}
	log.Debugf("looking for security group for instance %s", *ec2Instance.InstanceId)
	securityGroupsResult, err := ec2Svc.DescribeSecurityGroups(context.Background(), securityGroupQuery)
	if err != nil {
		return types.SecurityGroup{}, err
	}

	if len(securityGroupsResult.SecurityGroups) <= 0 {
		return types.SecurityGroup{}, fmt.Errorf("security group for ec2:%s not found", *ec2Instance.InstanceId)
	}

	log.Debugf("found %d security groups", len(securityGroupsResult.SecurityGroups))
	return securityGroupsResult.SecurityGroups[0], nil
}

func getRouteTablesForEc2(ec2Instance types.Instance, ec2Svc *ec2.Client) (types.RouteTable, error) {
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
		return types.RouteTable{}, fmt.Errorf("no route table found for ec2 with ip '%s'", *ec2Instance.PrivateIpAddress)
	}
	return routeTables.RouteTables[0], nil
}
