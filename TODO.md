Current work:
- [ ] 1. scenario - vpc peered ec2 -> sg -> rtb -> vpc peering -> rtb -> sg -> ec2 
  
- [ ] 2. scenario - tgw ec2 -> sg -> rtb -> tgw -> rtb -> sg -> ec2
    
- [ ] 3. scenario - same vpc ec2 -> sg -> rtb -> sg -> ec2

----------------------------------------------------


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
```
