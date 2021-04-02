# cir

Can I Reach

cir - app to check if packet will be able to flow from one machine to another
checks - subnets, routing, security groups, transit gateway etc

Visualize the connection?

TODO:
- caching - using local file system? - https://github.com/spf13/afero


given private ip address or public ip address and target
- find ec2
- find security group
- find if egress opened up to cidr range 

v ec2 - egress

aws ec2 describe-instances --filters "Name=network-interface.addresses.private-ip-address,Values=172.29.13.20"
aws ec2 describe-instances --filters "Name=ip-address,Values=172.29.13.20"

aws ec2 describe-security-groups --group-ids sg-032782582234889be

v ec2 - subnet
v ec2 - network acl
v ec2 - route table
v ec2 - routes
- nat gateway
- private connect
- igw
- tgw

command - draw - will draw the logical flow of the packet with components and where is the missing part

-----------------

v ec2 - ingress

sg group id
aws ec2 describe-instances --filters "Name=network-interface.addresses.private-ip-address,Values=172.29.13.20" | jq ".Reservations[0].Instances[0].SecurityGroups[0].GroupId"

1. check security group inbound, outbound options




IDEAS:
- visualise network topology


Maybe usefull librariers to check:
https://github.com/yl2chen/cidranger


```
These three scenarios and we are ready for open source
/Limitations:
- only tgw, vpc peering supported
- assuming one route table, one security group per ec2
- ignoring 0.0.0.0/0
```
