#!/bin/bash

# Command to run cargo fuzz
COMMAND="cargo fuzz run evm -- -rss_limit_mb=9999999999 -max_len=99999999"

# Initialize CRASH_PATH
CRASH_PATH=""

while true; do
    # Run the cargo fuzz command
    echo "Running: $COMMAND"
    OUTPUT="$($COMMAND)"
        
    # Find the crash path and store it in a variable
    CRASH_PATH=$(echo "$OUTPUT" | grep -o "cargo fuzz run evm artifacts/evm/crash-[a-zA-Z0-9]\+")
    # Check if the output contains "Finished with success"
    
    if [[ "$OUTPUT" == *"Finished with success"* ]]; then

        # Check if a crash path was found
        if [ -n "$CRASH_PATH" ]; then
            # Remove the crash file and contents
            echo "Deleting: $CRASH_PATH"
            rm -rf "$CRASH_PATH"
        else
            echo "No crash path found."
        fi
    else

        # No "Finished with success" message found
        echo "Execution failed."
        if [ -n "$CRASH_PATH" ]; then
            # Print the crash path if it exists
            echo "Crash path: $CRASH_PATH"
        fi
        break
    fi

    echo "========================================"
done

