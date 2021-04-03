IDEAS:

```
//TODO: what if network is in two AWS accounts?
//TODO: what if I need to change AWS credentials to query different resources
//TODO: ability to writes `check` and then run them from time to time in lambda? and alert if something is broken? or on demand
//TODO: if proxy hit -> ability to add proxy check to verify proxy configuration from task definition or yaml file
//TODO: file defined test scenarios -> f3 run test scenario during incident to verify if everything is correct!
//TODO: cir ec2.aws -> if 0.0.0.0/0 enabled - yes
//TODO: cir ec2.aws -> if 0.0.0.0/0 disabled - check for vpc endpoint if yes -> yes
//TODO: private links
//TODO: aws gcp azure - across boundaries
//TODO: if one ec2 not found then do analysis for only one side
//TODO: todo if port not specified create a list of ports that would be able to be sent through
//TODO: dest publioc internet to check if box can exit to public internet
//TODO: 0.0.0.0 handlinhg - if both of the ec2 instances have acess to public internet and dest,src points to igw - then its a match - but mention that its going through public internet

//TODO: non verbose - just show if it can connect or not if happy then just say happy - if not happy show details
//TODO: tgw attachements instead of just checking if TGW is enabled
//TODO: security group rule check - dont stop on one match - check if more rules match and display them
//TODO: security group check - add protolc as param and check if protocl matches - maybe show that for other protocol its opened up? (to show mistake?)
//TODO: handle multiple security groups
//TODO: handle multiple route tables
//TODO: support for nice visualization of the traffic  command - draw - will draw the logical flow of the packet with components and where is the missing part
caching - using local file system? - https://github.com/spf13/afero
//TODO: check network acl
//TODO: check egress firewall settings
//TODO: check direct connect
//TODO: check dns - route53 associations, private public dns, dns firewall
- dump whole network setup for vpc and draw it - all the connections
- visualise network topology
- AZURE 
- GCP
```

- define test scenarios for quick run of multiple connection checks - usefull on incident as a quick helper tool to verify if everything is fine on network layer

Usefull librareier to check:
- https://github.com/yl2chen/cidranger
