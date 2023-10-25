#!/bin/bash
#set -eo pipefail

prover=$1
degree=$2

# Get the latest temp directory in the Triggerers directory
trigger_results_dir="../../../results"
mkdir -p "$trigger_results_dir" || true

# Get the latest temp directory in the Provers home directory
prover_latest_dir=$(ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@"$PROVER_IP" "bash -s" <<EOF
ls -td -- "\$HOME"/CI_Prover_Benches/* | head -1
EOF
)

prover_target_dir="$prover_latest_dir/zkevm-circuits"
prover_results_dir="$prover_latest_dir/results"
echo "$prover_target_dir"

# Collect results from Prover
echo "Collecting results from $PROVER_IP:$prover_results_dir to TRIGGER_HOST:$trigger_results_dir"
scp -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@"$PROVER_IP":"$prover_results_dir"/*proverlog "$trigger_results_dir"/

# Enable bash Environment Variables for Prover
ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@"$PROVER_IP" "bash -s" <<EOF
echo "PermitUserEnvironment yes" | sudo tee -a /etc/ssh/sshd_config
sudo service sshd restart
EOF
sleep 10

# Collect cpu and memory metrics
scp -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ./sadf.sh ubuntu@"$PROVER_IP":~/
# shellcheck disable=SC2086
ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@$PROVER_IP "bash -s" <<EOF
BENCH_BEGIN=\$(cat /home/ubuntu/bench_begin)
echo "Bench began at \$BENCH_BEGIN"
mv /home/ubuntu/sadf.sh $prover_results_dir/
cd $prover_results_dir
./sadf.sh \$BENCH_BEGIN
EOF
scp -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@"$PROVER_IP":"$prover_results_dir"/*.stats "$trigger_results_dir"/

# Prepare for and run data processing and db persistence

l=$(echo "$prover" | tr -d '"')
circuit=$(echo "$l" |  awk '{print $1}')
time=$(date +%Y-%m-%d_%H-%M-%S)
test_id=$time-$circuit-$degree-Benchmark

cd "$trigger_results_dir"
tar -czvf ./"$test_id".tar.gz ./*proverlog ./*.stats

cp ../zkevm-circuits/.github/integrationBenchScripts/reporting*.py .
sudo cp *proverlog /var/www/www_logs/
proverlog="http://43.130.90.57/www_logs/"$(ls -t /var/www/www_logs | head -1)
instance_commitments=$(ls -t *proverlog | xargs cat | sed 's/\x1B\[[0-9;]*[JKmsu]//g' | egrep -o  "|.*instance.*" | egrep -o [0-9]+[\ ]+[0-9]+ | awk '{print $1}')
instance_evaluations=$(ls -t *proverlog | xargs cat | sed 's/\x1B\[[0-9;]*[JKmsu]//g' | egrep -o  "|.*instance.*" | egrep -o [0-9]+[\ ]+[0-9]+ | awk '{print $2}')
advice_commitments=$(ls -t *proverlog | xargs cat | sed 's/\x1B\[[0-9;]*[JKmsu]//g' | egrep -o  "|.*advice.*" | egrep -o [0-9]+[\ ]+[0-9]+ | awk '{print $1}')
advice_evaluations=$(ls -t *proverlog | xargs cat | sed 's/\x1B\[[0-9;]*[JKmsu]//g' | egrep -o  "|.*advice.*" | egrep -o [0-9]+[\ ]+[0-9]+ | awk '{print $2}')
fixed_commitments=$(ls -t *proverlog | xargs cat | sed 's/\x1B\[[0-9;]*[JKmsu]//g' | egrep -o  "|.*fixed.*" | egrep -o [0-9]+[\ ]+[0-9]+ | awk '{print $1}')
fixed_evaluations=$(ls -t *proverlog | xargs cat | sed 's/\x1B\[[0-9;]*[JKmsu]//g' | egrep -o  "|.*fixed.*" | egrep -o [0-9]+[\ ]+[0-9]+ | awk '{print $2}')
lookups_commitments=$(ls -t *proverlog | xargs cat | sed 's/\x1B\[[0-9;]*[JKmsu]//g' | egrep -o  "|.*lookups.*" | egrep -o [0-9]+[\ ]+[0-9]+ | awk '{print $1}')
lookups_evaluations=$(ls -t *proverlog | xargs cat | sed 's/\x1B\[[0-9;]*[JKmsu]//g' | egrep -o  "|.*lookups.*" | egrep -o [0-9]+[\ ]+[0-9]+ | awk '{print $2}')
equality_commitments=$(ls -t *proverlog | xargs cat | sed 's/\x1B\[[0-9;]*[JKmsu]//g' | egrep -o  "|.*equality.*" | egrep -o [0-9]+[\ ]+[0-9]+ | awk '{print $1}')
equality_evaluations=$(ls -t *proverlog | xargs cat | sed 's/\x1B\[[0-9;]*[JKmsu]//g' | egrep -o  "|.*equality.*" | egrep -o [0-9]+[\ ]+[0-9]+ | awk '{print $2}')
vanishing_commitments=$(ls -t *proverlog | xargs cat | sed 's/\x1B\[[0-9;]*[JKmsu]//g' | egrep -o  "|.*vanishing.*" | egrep -o [0-9]+[\ ]+[0-9]+ | awk '{print $1}')
vanishing_evaluations=$(ls -t *proverlog | xargs cat | sed 's/\x1B\[[0-9;]*[JKmsu]//g' | egrep -o  "|.*vanishing.*" | egrep -o [0-9]+[\ ]+[0-9]+ | awk '{print $2}')
multiopen_commitments=$(ls -t *proverlog | xargs cat | sed 's/\x1B\[[0-9;]*[JKmsu]//g' | egrep -o  "|.*multiopen.*" | egrep -o [0-9]+[\ ]+[0-9]+ | awk '{print $1}')
multiopen_evaluations=$(ls -t *proverlog | xargs cat | sed 's/\x1B\[[0-9;]*[JKmsu]//g' | egrep -o  "|.*multiopen.*" | egrep -o [0-9]+[\ ]+[0-9]+ | awk '{print $2}')
polycomm_commitments=$(ls -t *proverlog | xargs cat | sed 's/\x1B\[[0-9;]*[JKmsu]//g' | egrep -o  "|.*polycomm.*" | egrep -o [0-9]+[\ ]+[0-9]+ | awk '{print $1}')
polycomm_evaluations=$(ls -t *proverlog | xargs cat | sed 's/\x1B\[[0-9;]*[JKmsu]//g' | egrep -o  "|.*polycomm.*" | egrep -o [0-9]+[\ ]+[0-9]+ | awk '{print $2}')

circuit_cost=$(ls -t *proverlog | xargs cat | egrep -o "CircuitCost.*")

minimum_rows=$(ls -t *proverlog | xargs cat | egrep -o "^minimum_rows.*" | egrep -o "[0-9]+")
blinding_factors=$(ls -t *proverlog | xargs cat | egrep -o "^blinding_factors.*" | egrep -o "[0-9]+")
gates_count=$(ls -t *proverlog | xargs cat | egrep -o "^gates count.*" | egrep -o "[0-9]+")


sed -i '1i BENCH-PROVER;-1;UTC;LINUX-RESTART	(64 CPU)' mem.stats
sed -i '1i BENCH-PROVER;-1;UTC;LINUX-RESTART	(64 CPU)' cpu.stats
python3 reporting_main.py  "$proverlog" "1" "$prover" "$degree" "$test_id" \
"$instance_commitments" "$instance_evaluations" \
"$advice_commitments" "$advice_evaluations" \
"$fixed_commitments" "$fixed_evaluations" \
"$lookups_commitments" "$lookups_evaluations" \
"$equality_commitments" "$equality_evaluations" \
"$vanishing_commitments" "$vanishing_evaluations" \
"$multiopen_commitments" "$multiopen_evaluations" \
"$polycomm_commitments" "$polycomm_evaluations" \
"$circuit_cost" \
"$minimum_rows" "$blinding_factors" "$gates_count"

ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@"$PROVER_IP" "bash -s" <<EOF
sudo rm -rf $prover_results_dir
EOF

