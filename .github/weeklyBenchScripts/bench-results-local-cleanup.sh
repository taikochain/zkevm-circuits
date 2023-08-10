#!/bin/bash
echo "Performing cleanup..."
PROVER_INSTANCE=$(cat ~/prover_instance)
echo "Prover instance: $PROVER_INSTANCE"
tccli cvm TerminateInstances --InstanceIds "[\"$PROVER_INSTANCE\"]" --ReleasePrepaidDataDisk True
echo "Exiting bench-results-local-cleanup"
pkill ssh
exit 0
