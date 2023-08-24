#!/bin/bash

fuzz_directory="/home/krzychu/Develop/Taiko/github/zkevm-circuits/zkevm-circuits/fuzz"
cd $fuzz_directory
crash_directory="/home/krzychu/Develop/Taiko/github/zkevm-circuits/zkevm-circuits/fuzz/artifacts/fuzz_target_1"
raport_file=$fuzz_directory/fuzz_raport.txt

rm $raport_file

for file in "$crash_directory"/*; do
    if [ -f "$file" ]; then
        echo -e "\n############################################\n" | tee -a $raport_file
        echo "Processing file: $file" | tee -a $raport_file
        echo -e "\n###\n" | tee -a $raport_file
        cargo fuzz tmin fuzz_target_1 artifacts/fuzz_target_1/crash-c0c92a7454f2453a26cbe47dbd79c2fadbef9a23 2>&1 | grep -A 2 -B 1 -m 1 panicked | tee -a $raport_file
        echo -e "\n###\n" | tee -a $raport_file
        cargo fuzz fmt fuzz_target_1 $file 2>&1 | tee -a $raport_file
        echo -e "\n############################################\n"
    fi
done

