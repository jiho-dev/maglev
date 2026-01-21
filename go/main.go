package main

import (
	"fmt"
	"os"
)

var fileName string

func printHelp() {
	fmt.Printf("usage: %s [opts] [-- [dump-flows opts]] \n", os.Args[0])
	fmt.Printf("\n")
	fmt.Printf("options: \n")
	fmt.Printf("  -h, --help     : print this help\n")
	fmt.Printf("  --debug        : debug mode\n")
	fmt.Printf("  --file <name>  : flow file name\n")
	fmt.Printf("\n")

}

func getArgParam(args []string, curIdx *int) (string, error) {
	argLen := len(args)

	i := *curIdx
	if argLen > i+1 {
		val := args[i+1]
		(*curIdx)++

		return val, nil
	}

	err := fmt.Errorf("not enough args: curIdx %d > %d \n", i, argLen)
	return "", err
}

func parseArgs(args []string) {
	argLen := len(args)
	if argLen < 1 {
		return
	}

	for i := 0; i < argLen; i++ {
		arg := args[i]
		switch arg {
		case "-h", "--help":
			printHelp()
			os.Exit(0)
		case "--file":
			if p, err := getArgParam(args, &i); err != nil {
				fmt.Printf("%s\n", err)
				os.Exit(1)
			} else {
				fileName = p
			}
			continue
		}
	}

}

func main() {
	var err error

	defer func() {
		if err != nil {
			os.Exit(1)
		}
	}()

	parseArgs(os.Args)

	VerifyCrc()
	VerifyHashByte()
	VerifyHashBytes()
	VerifyJHash4Bytes()
	VerifyJhashBytes()
	VerifyMHash4Bytes()
	VerifyMhashBytes()

}
