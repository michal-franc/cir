# cir - Can I Reach
A tool to check network connections problems in your cloud network setup. This tool verifies if from your cloud point of view resources are able to talk to each other communicate. It will perform checks using cloud provider api (AWS SDK) and check things like - security group rules, routing in subnets, vpc peering etc

### Example output

Positive
```
cir run --from 10.44.7.232 --to 10.99.4.9 --port 3128
checking if '10.44.7.232' can reach '10.99.4.9 on port '3128'
Check if i-0def11e311aee206c can reach i-075e1119ce9103d62
---------------------------
(source and dest - in different vpcs)
✓ security groups:
✓ -> found outbound rule pointing at ipv4 cidr range 10.99.0.0/16
✓ -> found inbound rule pointing at ipv4 cidr range 10.0.0.0/8

✓ subnets:
✓ -> found route in route table 'rtb-1a11d1d61dd1e8c67' with range '10.99.0.0/16'
✓ -> found route in route table 'rtb-0d70f88fcb217b113' with range '10.44.0.0/16'

✓ vpc connection:
✓ -> source and dest connected using tgw: tgw-0c104210f1c1d7b0c
✓ -> tgw - tgw-0c104210f1c1d7b0c - is available
---------------------------
```
Negative
```
cir run --from 10.44.7.232 --to 10.99.4.9 --port 3128
checking if '10.44.7.232' can reach '10.99.4.9 on port '3128'
Check if i-0def11e311aee206c can reach i-075e1119ce9103d62
---------------------------
(source and dest - in different vpcs)
✓ security groups:
✓ -> found outbound rule pointing at ipv4 cidr range 10.99.0.0/16
✓ -> found inbound rule pointing at ipv4 cidr range 10.0.0.0/8

x subnets:
✓ -> found route in route table 'rtb-1a11d1d61dd1e8c67' with range '10.99.0.0/16'
x -> found no route in route table 'rtb-0d70f88fcb217b113'

✓ vpc connection:
✓ -> source and dest connected using tgw: tgw-0c104210f1c1d7b0c
✓ -> tgw - tgw-0c104210f1c1d7b0c - is available
---------------------------
```

### Motivation
As engineer, I have spent a lot of time debugging connection problems on AWS. Things like missing security group, incorrect cidr range in route table, not active VPC peering etc. This is a tool to automate some of these verification processes. It is to be a quick check tool running from cli. For more comprehensive tool check AWS [`VPC Reachability Analyzer`](https://aws.amazon.com/blogs/aws/new-vpc-insights-analyzes-reachability-and-visibility-in-vpcs/).

### Current limitations
This is early on in development and not everything is supported. At the moment I am focusing on covering scenarios useful for my current client.
- only AWS supported
- only resources belonging to same AWS account supported
- only ec2 supported
- only tgw, vpc peering supported if two vpcs involved
- only one route table, one security group per ec2, subnet supported
- there are many more limitations at the moment :)

### Usage
You need to have AWS credentials available in `ENV`, `.aws` etc

Querying by `ip`
```
cir run --from ip:10.121.1.232 --to ip:10.133.4.9 --port 3128
```

Querying by `name`.
```
cir run --from name:awesome-ec2 --to name:another-great-ec2 --port 3128
```
If there are more than `1` ec2 instances - all sources are checked if can reach all destinations and summary is displayed if all are passing.
Only the ones failing are shown in details. You can force detail display for all checks with `--detailed` flag.

### Installation
It was tested on `linux`.  
Binaries for `windows` and `mac (darwin)` are available but are untested yet.

Download binary from github releases and unpack it to your `PATH` folder.

Using Go Get
```
go get -u github.com/michal-franc/cir/cmd/cir
```
