TODO to ISSUES (maybe in order):
// Improvements to exisitng checks
- [ ] what if source route points to TGW but destination route points to VPC Peering?
    - we need to throw an error that there is a mismatch
- [ ] security group check - add optional protolc as param and check if protocl matches - maybe show that for other protocol its opened up? (to show mistake?)
- [ ] handle multiple security groups
  - security group rule check - dont stop on one match - check if more rules match and display them
- [ ] handle multiple route tables
      
- [ ] TGW: attachements instead of just checking if TGW is enabled
 
// New Features 
- [ ] ability to specifiy Tag name and search for boxes using it
    - this is required for scenario based testing
    - if multiple boxes found - check all of them
- [ ] support lambda reachability - to ec2
- [ ] support elastic search reachability
- [ ] support rds reachability
- [ ] support ec2 box able to reach ecs - to check if its part of ecs cluster
- [ ] test scenarios: `check` and then run them from time to time in lambda? and alert if something is broken? or on demand
  - file defined test scenarios -> f3 run test scenario during incident to verify if everything is correct!
  - define test scenarios for quick run of multiple connection checks - usefull on incident as a quick helper tool to verify if everything is fine on network layer
- [ ] Improve check logic so that we cna keep em separated from analyzer - for improved scalability when adding new checks
- [ ] different print output: support for nice visualization of the traffic  command - draw - will draw the logical flow of the packet with components and where is the missing part
- [ ] visualise network topology - for 2 vpcs - generate diagrams  (maybe using https://github.com/k1LoW/ndiag)
  - dump whole network setup for vpc and draw it - all the connections
- [ ] eks networking 
    
- if one ec2 not found then do analysis for only one side
  if port not specified create a list of ports that would be able to be sent through
 
// New checks 
- [ ] cir ec2.aws -> if 0.0.0.0/0 enabled - yes
    - cir ec2.aws -> if 0.0.0.0/0 disabled - check for vpc endpoint if yes -> yes
      
- [ ] dest/source public internet to check if box can exit to public internet
- [ ] 0.0.0.0 handlinhg - if both of the ec2 instances have acess to public internet and dest,src points to igw - then its a match - but mention that its going through public internet
- [ ] support for egress only gateway
- [ ] check network acl
- [ ] check egress firewall settings
- [ ] check direct connect
- [ ] check dns - route53 associations, private public dns, dns firewall

IDEAS:

```
//TODO: what if network is in two AWS accounts?
//TODO: what if I need to change AWS credentials to query different resources
//TODO: if proxy hit -> ability to add proxy check to verify proxy configuration from task definition or yaml file
//TODO: private links
//TODO: aws gcp azure - across boundaries

//TODO: non verbose - just show if it can connect or not if happy then just say happy - if not happy show details
caching - using local file system? - https://github.com/spf13/afero
- AZURE 
- GCP
```


Usefull librareier to check:
- https://github.com/yl2chen/cidranger
