package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

type SshConfig struct {
	Filename   string
	SshIp      string
	SshUser    string
	NumClients uint32
	Timeout    uint32
	Interval   uint32
	Cmd        string
}

func printHelp() {
	fmt.Printf("usage: %s [opts] [-- [dump-flows opts]] \n", os.Args[0])
	fmt.Printf("\n")
	fmt.Printf("options: \n")
	fmt.Printf("  -h, --help     : print this help\n")
	fmt.Printf("  --debug        : debug mode\n")
	fmt.Printf("  --file <name>  : flow file name\n")
	fmt.Printf("  --ip <name>    : ip\n")
	fmt.Printf("  --port <port>  : port\n")
	fmt.Printf("  --user <name>  : user\n")
	fmt.Printf("  --clients <name>: num of clients\n")
	fmt.Printf("  --timeout <sec>: timeout sec\n")
	fmt.Printf("  --interval <sec>: interval sec\n")
	fmt.Printf("  --cmd <cms>: command\n")
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

func parseArgs(args []string) *SshConfig {
	home, _ := os.UserHomeDir()
	cfg := &SshConfig{
		SshIp:      "127.0.0.1",
		SshUser:    "ubuntu",
		Filename:   home + "/.ssh/id_rsa",
		NumClients: 1,
		Timeout:    10,
		Interval:   2,
		Cmd:        "ls",
	}
	argLen := len(args)
	if argLen < 1 {
		return cfg
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
				cfg.Filename = p
			}
		case "--ip":
			if p, err := getArgParam(args, &i); err != nil {
				fmt.Printf("%s\n", err)
				os.Exit(1)
			} else {
				cfg.SshIp = p
			}
		case "--user":
			if p, err := getArgParam(args, &i); err != nil {
				fmt.Printf("%s\n", err)
				os.Exit(1)
			} else {
				cfg.SshUser = p
			}
		case "--cmd":
			if p, err := getArgParam(args, &i); err != nil {
				fmt.Printf("%s\n", err)
				os.Exit(1)
			} else {
				cfg.Cmd = p
			}
		case "--clients":
			if p, err := getArgParam(args, &i); err != nil {
				fmt.Printf("%s\n", err)
				os.Exit(1)
			} else {
				n, _ := strconv.Atoi(p)
				if n > 0 {
					cfg.NumClients = uint32(n)
				}
			}
		case "--timeout":
			if p, err := getArgParam(args, &i); err != nil {
				fmt.Printf("%s\n", err)
				os.Exit(1)
			} else {
				n, _ := strconv.Atoi(p)
				if n > 0 {
					cfg.Timeout = uint32(n)
				}
			}
		case "--interval":
			if p, err := getArgParam(args, &i); err != nil {
				fmt.Printf("%s\n", err)
				os.Exit(1)
			} else {
				n, _ := strconv.Atoi(p)
				if n > 0 {
					cfg.Interval = uint32(n)
				}
			}
		default:
			fmt.Printf("Unknow opt: %s\n", arg)
		}
	}

	return cfg
}

// const timeFormat = time.RFC3339
// const timeFormat = "2006-02-01T15:04:05Z"
const timeFormat = "2006-01-02T15:04:05"

type logWriter struct{}

func (lw *logWriter) Write(bs []byte) (int, error) {
	return fmt.Print(time.Now().Format(timeFormat), " ", string(bs))
}

func main() {
	var err error
	log.SetFlags(0)
	//log.SetFlags(log.LstdFlags)
	log.SetOutput(new(logWriter))

	defer func() {
		if err != nil {
			os.Exit(1)
		}
	}()

	cfg := parseArgs(os.Args)

	/*

		VerifyCrc()
		VerifyHashByte()
		VerifyHashBytes()
		VerifyJHash4Bytes()
		VerifyJhashBytes()
		//VerifyMHash4Bytes()
		//VerifyMhashBytes()
	*/

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("got signal: %v...\n", sig)
		cancel()
	}()

	log.Printf("SSH Config=%+v \n", *cfg)
	run_ssh(ctx, cfg)
}
