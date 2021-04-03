package scanner

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	log "github.com/sirupsen/logrus"
)

type ResourceMetaData struct {
	PrivateIp     string
	VpcId         string
	SecurityGroup types.SecurityGroup
	SubnetId      string
	RouteTable    types.RouteTable
}

type AwsData struct {
	Source      *ResourceMetaData
	Destination *ResourceMetaData
}

func ScanAwsEc2(client *ec2.Client, sourceIp string, destinationIp string) (*AwsData, error) {
	ec2InstanceSource, err := findEC2ByPrivateIp(sourceIp, client)
	if err != nil {
		return &AwsData{}, err
	}

	ec2InstanceDestination, err := findEC2ByPrivateIp(destinationIp, client)
	if err != nil {
		return &AwsData{}, err
	}

	securityGroupsDestination, err := getSecurityGroupsById(ec2InstanceDestination, client)
	if err != nil {
		return &AwsData{}, err
	}

	securityGroupsSource, err := getSecurityGroupsById(ec2InstanceSource, client)
	if err != nil {
		return &AwsData{}, err
	}

	routeTableSource, err := getRouteTablesForEc2(ec2InstanceSource, client)
	if err != nil {
		return &AwsData{}, err
	}

	routeTableDestination, err := getRouteTablesForEc2(ec2InstanceSource, client)
	if err != nil {
		return &AwsData{}, err
	}

	return &AwsData{
		Source: &ResourceMetaData{
			PrivateIp:     *ec2InstanceSource.PrivateIpAddress,
			SecurityGroup: (*securityGroupsSource)[0],
			VpcId:         *ec2InstanceSource.VpcId,
			SubnetId:      *ec2InstanceSource.SubnetId,
			RouteTable:    *routeTableSource,
		},
		Destination: &ResourceMetaData{
			PrivateIp:     *ec2InstanceDestination.PrivateIpAddress,
			SecurityGroup: (*securityGroupsDestination)[0],
			VpcId:         *ec2InstanceDestination.VpcId,
			SubnetId:      *ec2InstanceDestination.SubnetId,
			RouteTable:    *routeTableDestination,
		},
	}, nil
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

	if len(ec2result.Reservations[0].Instances) > 1 {
		return nil, fmt.Errorf("multiple ec2 found for given ip '%s'", privateIp)
	}

	return &ec2result.Reservations[0].Instances[0], nil
}

func getSecurityGroupsById(ec2Instance *types.Instance, ec2Svc *ec2.Client) (*[]types.SecurityGroup, error) {
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

func getRouteTablesForEc2(ec2Instance *types.Instance, ec2Svc *ec2.Client) (*types.RouteTable, error) {
	log.Debug("Checking subnet routing table")
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
	if len(routeTables.RouteTables) <= 0 {
		return nil, fmt.Errorf("no route table found for ec2 with ip '%s'", *ec2Instance.PrivateIpAddress)
	}
	return &routeTables.RouteTables[0], nil
}
