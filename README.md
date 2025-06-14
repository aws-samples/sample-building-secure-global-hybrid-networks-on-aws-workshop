# Building Secure Global Hybrid Networks on AWS with AWS Cloud WAN and AWS Network Firewall

This repository contains the CloudFormation templates used in the AWS Workshop: [Building Secure Global Hybrid Networks on AWS with AWS Cloud WAN and AWS Network Firewall](https://catalog.us-east-1.prod.workshops.aws/workshops/cdef9a06-8156-4669-9e6a-6eb83e4a5adc).

## Workshop Link

For detailed instructions, please follow the workshop guide at:
[https://catalog.us-east-1.prod.workshops.aws/workshops/cdef9a06-8156-4669-9e6a-6eb83e4a5adc](https://catalog.us-east-1.prod.workshops.aws/workshops/cdef9a06-8156-4669-9e6a-6eb83e4a5adc)

## AWS Hosted Events

It's recommended to run through AWS workshops at AWS hosted events, like [Activation Days](https://aws-experience.com/amer/smb/events/series/activation-days), where AWS provides temporary accounts with workshop resources.

This workshop has been published open source mainly to allow the CloudFormation templates to be referencable.

## Deployment Instructions

The workshop environment can be deployed using a single CloudFormation stack (`resources.yaml`), which uses CloudFormation StackSets to deploy resources across multiple regions.

### Important Region Information

**IMPORTANT**: This deployment creates resources in the following AWS regions:
- **US East (Ohio) - us-east-2** (primary region)
- **EU (Frankfurt) - eu-central-1** (secondary region)

### Deployment Steps

1. Clone this repository
2. Navigate to the AWS CloudFormation console in **US East (Ohio) - us-east-2**
3. Choose "Create stack" > "With new resources (standard)"
4. Upload the `nfw-cloudwan-workshop/cfn-templates/resources.yaml` file
5. Follow the prompts to create the stack (no parameters required)
6. Wait for the stack creation to complete (approximately 20-30 minutes)

### Regional Deployment Options

If you don't want to deploy resources in the EU (Frankfurt) region, you can modify the `resources.yaml` file to remove the `Region2SolutionStackSet` resource before deployment. 

**Note**: If you choose not to deploy the eu-central-1 resources:
- You will not be able to complete Module 3 of the workshop
- All other modules will function normally

## Cleanup

To delete all resources created by this workshop:
1. Navigate to the CloudFormation console in **US East (Ohio) - us-east-2**
2. Select the main resources stack
3. Choose "Delete"
4. The stack includes a custom resource that will automatically clean up all StackSet instances and StackSets

## Estimated Costs

The following is an estimated cost to run this workshop for one day, based on actual usage data. These costs reflect the current two-region setup (us-east-2 and eu-central-1) with resources deployed across two Availability Zones in each region to simulate a highly available architecture:

| Service | Estimated Cost (24 hours) |
|---------|---------------------------|
| AWS Network Firewall | $41.09 |
| AWS Cloud WAN | $39.15 |
| EC2-Other (EBS, etc.) | $9.13 |
| VPC | $5.04 |
| EC2 Instances | $4.38 |
| CloudWatch | $0.48 |
| Other Services | $0.16 |
| **Total** | **~$99.44** |

*Note: These are estimates based on actual usage data. Your costs may vary depending on your specific implementation, usage patterns, and any applicable Free Tier benefits.*

**Future Cost Optimization:** We plan to scope down these templates in the future to be more cost-conscious, deploying fewer resources in only one Availability Zone per region. This will allow the workshop to be completed for the lowest cost possible while still demonstrating the core concepts.

