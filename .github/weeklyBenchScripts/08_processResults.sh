#!/bin/bash
set -e
#set -x

prnumber=1
label=$1
degree=$2

# Get the latest temp directory in the home directory
latest_dir=$(ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@$PROVER_IP "bash -s" <<EOF
ls -td -- "\$HOME"/CI_Prover_Benches/* | head -1
EOF
)

base_dir="$latest_dir"
results_dir="$latest_dir/results"
target_dir="$base_dir/zkevm-circuits"
echo $target_dir

echo "Collecting results from $PROVER_IP:$target_dir"
mkdir -p results/$label
scp -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@$PROVER_IP:$target_dir/*proverlog ./results/$label/
scp -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ./sadf.sh ubuntu@$PROVER_IP:~/
ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@$PROVER_IP "bash -s" <<EOF
mkdir -p $results_dir
mv ~/sadf.sh $results_dir/
cd $results_dir
./sadf.sh
rm -f sadf.sh
EOF

scp -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@$PROVER_IP:$results_dir/*.stats ./results/$label/


l=$(echo $label | tr -d '"')
circuit=$(echo $l |  awk '{print $1}')
time=$(date +%Y-%m-%d_%H-%M-%S)
test_id=$time-$circuit-$degree-Benchmark

cd results/$label
tar -czvf ./$test_id.tar.gz ./*proverlog ./*.stats
#aws s3 cp ./$test_id.tar.gz s3://zkevm-chain-testing --profile cirunner
#echo "Log file uploaded at : https://zkevm-chain-testing.s3.eu-central-1.amazonaws.com/$test_id"".tar.gz"
cp ../../reporting*.py .
sudo cp *proverlog /var/www/www_logs/
proverlog="http://43.130.90.57/www_logs/"$(ls -t /var/www/www_logs | head -1)
python3 reporting_main.py  "$proverlog" "$prnumber" "$circuit" "$degree" "$test_id"

ssh -i ~/.ssh/bench.pem -o StrictHostKeyChecking=no ubuntu@$PROVER_IP "bash -s" <<EOF
rm -f $target_dir/*proverlog
rm -f ~/*.stats
EOF

