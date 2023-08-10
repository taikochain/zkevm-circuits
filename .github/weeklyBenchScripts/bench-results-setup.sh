#!/bin/bash
GITHUB_RUN_ID=$1

PROVER_INSTANCE=$(tccli cvm RunInstances --InstanceChargeType POSTPAID_BY_HOUR --InstanceChargePrepaid '{"Period":1,"RenewFlag":"DISABLE_NOTIFY_AND_MANUAL_RENEW"}' --Placement '{"Zone":"na-toronto-1"}' --InstanceType S3.16XLARGE256 --ImageId img-487zeit5 --SystemDisk '{"DiskType":"CLOUD_BSSD", "DiskSize":80}' --InternetAccessible '{"InternetChargeType":"TRAFFIC_POSTPAID_BY_HOUR","InternetMaxBandwidthOut":10,"PublicIpAssigned":true}' --InstanceCount 1 --InstanceName BENCH-PROVER --LoginSettings '{"KeyIds":[ "skey-au79yarf" ]}' --SecurityGroupIds '["sg-c3jtjz5g"]' --HostName BENCH-PROVER | egrep -o ins-[0-9a-zA-Z]*)
#PROVER_INSTANCE=$(tccli cvm RunInstances --InstanceChargeType POSTPAID_BY_HOUR --InstanceChargePrepaid '{"Period":1,"RenewFlag":"DISABLE_NOTIFY_AND_MANUAL_RENEW"}' --Placement '{"Zone":"eu-frankfurt"}' --InstanceType S5.16XLARGE256 --ImageId img-487zeit5 --SystemDisk '{"DiskType":"CLOUD_BSSD", "DiskSize":80}' --InternetAccessible '{"InternetChargeType":"TRAFFIC_POSTPAID_BY_HOUR","InternetMaxBandwidthOut":10,"PublicIpAssigned":true}' --InstanceCount 1 --InstanceName BENCH-PROVER --LoginSettings '{"KeyIds":[ "skey-au79yarf" ]}' --SecurityGroupIds '["sg-ajrlphkl"]' --HostName BENCH-PROVER | egrep -o ins-[0-9a-zA-Z]*)
#PROVER_INSTANCE=$(tccli cvm RunInstances --InstanceChargeType POSTPAID_BY_HOUR --InstanceChargePrepaid '{"Period":1,"RenewFlag":"DISABLE_NOTIFY_AND_MANUAL_RENEW"}' --Placement '{"Zone":"na-ashburn-2"}' --InstanceType S3.MEDIUM2 --ImageId img-487zeit5 --SystemDisk '{"DiskType":"CLOUD_BSSD", "DiskSize":50}' --InternetAccessible '{"InternetChargeType":"TRAFFIC_POSTPAID_BY_HOUR","InternetMaxBandwidthOut":10,"PublicIpAssigned":true}' --InstanceCount 1 --InstanceName BENCH-PROVER --LoginSettings '{"KeyIds":[ "skey-au79yarf" ]}' --SecurityGroupIds '["sg-ajrlphkl"]' --HostName BENCH-PROVER | egrep -o ins-[0-9a-zA-Z]*)
echo "$PROVER_INSTANCE" > $HOME/CI_Github_Trigger/$GITHUB_RUN_ID/prover_instance
echo "Prover instance at trigger: "
cat $HOME/CI_Github_Trigger/$GITHUB_RUN_ID/prover_instance
sleep 60
exit 0
