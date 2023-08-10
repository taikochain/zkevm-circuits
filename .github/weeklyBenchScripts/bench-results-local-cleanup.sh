#!/bin/bash
echo "Performing cleanup..."
echo "Prover instance: "
cat ~/prover_instance_weekly
PROVER_INSTANCE=$(cat \~/prover_instance_weekly)
echo "Prover instance at cleanup: $PROVER_INSTANCE"
tccli cvm TerminateInstances --InstanceIds "[\"$PROVER_INSTANCE\"]" --ReleasePrepaidDataDisk True
echo "Exiting bench-results-local-cleanup"
pkill ssh
exit 0
