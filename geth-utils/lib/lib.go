package main

/*
   #include <stdlib.h>
*/
import "C"
import (
	"bytes"
	"encoding/json"
	"fmt"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// TODO: Add proper error handling.  For example, return an int, where 0 means
// ok, and !=0 means error.
//
//export CreateTrace
func CreateTrace(configStr *C.char) *C.char {
	// var config gethutil.TraceConfig
	// err := json.Unmarshal([]byte(C.GoString(configStr)), &config)
	// if err != nil {
	// 	return C.CString(fmt.Sprintf("Failed to unmarshal config, err: %v", err))
	// }

	// executionResults, err := gethutil.Trace(config)
	// if err != nil {
	// 	return C.CString(fmt.Sprintf("Failed to run Trace, err: %v", err))
	// }

	// bytes, err := json.MarshalIndent(executionResults, "", "  ")
	// if err != nil {
	// 	return C.CString(fmt.Sprintf("Failed to marshal []ExecutionResult, err: %v", err))
	// }

	return C.CString("")
}

//export FreeString
func FreeString(str *C.char) {
	C.free(unsafe.Pointer(str))
}

//export BlockRlp
func BlockRlp(str *C.char) *C.char {
	var block types.Block
	err := json.Unmarshal([]byte(C.GoString(str)), &block)
	if err != nil {
		return C.CString(fmt.Sprintf("Failed to run BlockHash, err: %v", err))
	}
	buf := new(bytes.Buffer)
	err = block.EncodeRLP(buf)
	if err != nil {
		return C.CString(fmt.Sprintf("Failed to run BlockHash, err: %v", err))
	}

	result := common.Bytes2Hex(buf.Bytes())
	return C.CString(result)
}

func main() {}
