package main

import (
	"bytes"
	"context"
	"io/ioutil"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

func run_ssh(ctx context.Context, cfg *SshConfig) error {

	key, err := ioutil.ReadFile(cfg.Filename)
	if err != nil {
		log.Printf("failed to read key: %s, %v \n", cfg.Filename, err)
		return err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Printf("failed to parse key: %v \n", err)
		return err
	}

	config := &ssh.ClientConfig{
		Timeout: time.Duration(cfg.Timeout) * time.Second,
		User:    cfg.SshUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	var wg sync.WaitGroup

	sshCmd := func(id uint32) {
		log.Printf("Start ssh client: id=%d\n", id)
		defer func() {
			log.Printf("Stop ssh client: id=%d\n", id)
			wg.Done()
		}()

		client, err1 := ssh.Dial("tcp", cfg.SshIp, config)
		if err1 != nil {
			log.Printf("failed to connect server: id=%d, ipAddr=%s, %v \n", id, cfg.SshIp, err1)
			return
		} else if client == nil {
			log.Printf("client is nil: id=%d, ipAddr=%s, %v \n", id, cfg.SshIp, err1)
			return
		}

		log.Printf("Connected to the server: client-%d -> %s \n", id, cfg.SshIp)
		defer func() {
			client.Close()
			log.Printf("Disconnected to the server: client-%d -> %s \n", id, cfg.SshIp)
		}()

		var b bytes.Buffer

		to := time.NewTicker(time.Duration(cfg.Interval) * time.Second)
		defer to.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Printf("stopping ssh: id=%d, %v\n", id, ctx.Err())
				//session.Signal(ssh.SIGKILL)
				return
			case <-to.C:
				session, err2 := client.NewSession()
				if err2 != nil {
					log.Printf("failed to open a new cmd channel: id=%d, %v\n", id, err2)
					return
				}

				//log.Printf("Open a new cmd channel: client-%d -> %s \n", id, cfg.SshIp)
				defer func() {
					session.Close()
					//log.Printf("Closed the new cmd channel: client-%d -> %s \n", id, cfg.SshIp)
				}()

				session.Stdout = &b
				if err2 = session.Run(cfg.Cmd); err2 != nil {
					log.Printf("failed to run cmd: id=%d, cmd=%s, %v\n", id, cfg.Cmd, err2)
					return
				} else {
					log.Printf("ssh-%d: `%s` succeeded\n", id, cfg.Cmd)
				}
			}
		}
	}

	for i := uint32(1); i <= cfg.NumClients; i++ {
		wg.Add(1)
		go sshCmd(i)
	}

	log.Printf("Waiting for stoppting all ssh clients...\n")
	wg.Wait()
	log.Printf("Stopped all ssh clients\n")

	return nil
}
