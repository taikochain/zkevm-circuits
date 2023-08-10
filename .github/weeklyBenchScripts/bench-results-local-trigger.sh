#!/bin/bash
cd "$(dirname "$0")" || exit 1

PROVER_INSTANCE=$(tccli cvm RunInstances --InstanceChargeType POSTPAID_BY_HOUR --InstanceChargePrepaid '{"Period":1,"RenewFlag":"DISABLE_NOTIFY_AND_MANUAL_RENEW"}' --Placement '{"Zone":"na-toronto-1"}' --InstanceType S3.16XLARGE256 --ImageId img-487zeit5 --SystemDisk '{"DiskType":"CLOUD_BSSD", "DiskSize":80}' --InternetAccessible '{"InternetChargeType":"TRAFFIC_POSTPAID_BY_HOUR","InternetMaxBandwidthOut":10,"PublicIpAssigned":true}' --InstanceCount 1 --InstanceName BENCH-PROVER --LoginSettings '{"KeyIds":[ "skey-au79yarf" ]}' --SecurityGroupIds '["sg-c3jtjz5g"]' --HostName BENCH-PROVER | egrep -o ins-[0-9a-zA-Z]*)
#PROVER_INSTANCE=$(tccli cvm RunInstances --InstanceChargeType POSTPAID_BY_HOUR --InstanceChargePrepaid '{"Period":1,"RenewFlag":"DISABLE_NOTIFY_AND_MANUAL_RENEW"}' --Placement '{"Zone":"eu-frankfurt"}' --InstanceType S5.16XLARGE256 --ImageId img-487zeit5 --SystemDisk '{"DiskType":"CLOUD_BSSD", "DiskSize":80}' --InternetAccessible '{"InternetChargeType":"TRAFFIC_POSTPAID_BY_HOUR","InternetMaxBandwidthOut":10,"PublicIpAssigned":true}' --InstanceCount 1 --InstanceName BENCH-PROVER --LoginSettings '{"KeyIds":[ "skey-au79yarf" ]}' --SecurityGroupIds '["sg-ajrlphkl"]' --HostName BENCH-PROVER | egrep -o ins-[0-9a-zA-Z]*)
#PROVER_INSTANCE=$(tccli cvm RunInstances --InstanceChargeType POSTPAID_BY_HOUR --InstanceChargePrepaid '{"Period":1,"RenewFlag":"DISABLE_NOTIFY_AND_MANUAL_RENEW"}' --Placement '{"Zone":"na-ashburn-2"}' --InstanceType S3.MEDIUM2 --ImageId img-487zeit5 --SystemDisk '{"DiskType":"CLOUD_BSSD", "DiskSize":50}' --InternetAccessible '{"InternetChargeType":"TRAFFIC_POSTPAID_BY_HOUR","InternetMaxBandwidthOut":10,"PublicIpAssigned":true}' --InstanceCount 1 --InstanceName BENCH-PROVER --LoginSettings '{"KeyIds":[ "skey-au79yarf" ]}' --SecurityGroupIds '["sg-ajrlphkl"]' --HostName BENCH-PROVER | egrep -o ins-[0-9a-zA-Z]*)
echo "$PROVER_INSTANCE" > ~/prover_instance_weekly
echo "Prover instance at trigger: "
cat \~/prover_instance_weekly
sleep 60

export PROVER_IP=$(tccli cvm DescribeInstances --InstanceIds "[\"$PROVER_INSTANCE\"]" | grep -A 1 PublicIpAddress | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
echo "Prover IP: $PROVER_IP"

rm ~/.ssh/known_hosts*

ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@$PROVER_IP "bash -s" -- <00_installGo.sh
ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@$PROVER_IP "bash -s" -- <00_installRust.sh
ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@$PROVER_IP "bash -s" -- <01_installDeps.sh
ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@$PROVER_IP "bash -s" -- <02_setup.sh

run_single_benchmark() {
  local DEGREE=$1
  local CIRCUIT=$2

  ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@$PROVER_IP "bash -s" -- <03_prepareProver.sh
  ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@$PROVER_IP "bash -s" -- <04_clone.sh
  ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@$PROVER_IP "bash -s" -- <05_build.sh
  ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@$PROVER_IP "bash -s" -- <06_rsSysstat.sh &
  sleep 5

  ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@$PROVER_IP "bash -s" -- "$DEGREE" "$CIRCUIT" <07_execBench.sh
  chmod u+x 08_processResults.sh
  ./08_processResults.sh "$CIRCUIT" "$DEGREE"
}

words="exp evm tx bytecode state pi copy super keccak"

for word in $words; do
  case "$word" in
  evm)
    # Run script for evm
    echo "Running script for evm..."
    run_single_benchmark 19 evm
    ;;
  keccak)
    # Run script for keccak
    echo "Running script for keccak..."
    run_single_benchmark 19 keccak
    ;;
  state)
    # Run script for state
    echo "Running script for state..."
    run_single_benchmark 19 state
    ;;
  tx)
    # Run script for tx
    echo "Running script for tx..."
    run_single_benchmark 19 tx
    ;;
  super)
    # Run script for super
    echo "Running script for super..."
    run_single_benchmark 9 super
    ;;
  bytecode)
    # Run script for bytecode
    echo "Running script for bytecode..."
    run_single_benchmark 19 bytecode
    ;;
  pi)
    # Run script for pi
    echo "Running script for pi..."
    run_single_benchmark 19 pi
    ;;
  exp)
    # Run script for exp
    echo "Running script for exp..."
    run_single_benchmark 19 exp
    ;;
  copy)
    # Run script for copy
    echo "Running script for copy..."
    run_single_benchmark 19 copy
    ;;
  *)
    echo "Unknown word: $word"
    ;;
  esac
done

sudo rm -rf "$HOME/CI_Github_Trigger/"