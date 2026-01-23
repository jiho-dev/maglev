package main

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

func run_cmd(ctx context.Context, id uint32, client *ssh.Client, cfg *SshConfig) error {
	session, err2 := client.NewSession()
	if err2 != nil {
		return fmt.Errorf("failed to open a new cmd channel: id=%d, %v", id, err2)
	}

	//log.Printf("Open a new cmd channel: client-%d -> %s \n", id, cfg.SshIp)
	defer func() {
		session.Close()
		//log.Printf("Closed the new cmd channel: client-%d -> %s \n", id, cfg.SshIp)
	}()
	var outBuf bytes.Buffer
	var errBuf bytes.Buffer

	session.Stdout = &outBuf
	session.Stderr = &errBuf
	if err2 = session.Run(cfg.Cmd); err2 != nil {
		return fmt.Errorf("failed to run cmd: id=%d, cmd=%s, err=[%s, %v]",
			id, cfg.Cmd, errBuf.String(), err2)
	} else {
		//log.Printf("ssh-%d: `%s` succeeded\n", id, cfg.Cmd)
		hname := strings.TrimSpace(outBuf.String())
		log.Printf("ssh-%d: %s\n", id, hname)

		cfg.SetHostName(id, hname)
	}

	return nil
}

func (cfg *SshConfig) SetHostName(id uint32, name string) {
	cfg.lock.Lock()
	defer cfg.lock.Unlock()

	ci, ok := cfg.clients[id]
	if !ok {
		ci = &ClientInfo{
			HostName: name,
		}
		cfg.clients[id] = ci
	} else if ci.HostName != name {
		ci.HostName = name
	}
}

func (cfg *SshConfig) SetSshClient(id uint32, client *ssh.Client) {
	cfg.lock.Lock()
	defer cfg.lock.Unlock()

	ci, ok := cfg.clients[id]
	if !ok {
		ci = &ClientInfo{
			Client: client,
		}
		cfg.clients[id] = ci
	} else {
		ci.Client = client
	}
}

func (cfg *SshConfig) DeleteSshClient(id uint32) {
	cfg.lock.Lock()
	defer cfg.lock.Unlock()

	delete(cfg.clients, id)
}

func (cfg *SshConfig) Clean() []string {
	var stuck []string

	for id, ci := range cfg.clients {
		log.Printf("ssh-%d: killed because of stuck\n", id)
		if ci.Client != nil {
			ci.Client.Close()
		}

		stuck = append(stuck, fmt.Sprintf("ssh-%d: %s - stuck", id, ci.HostName))
	}

	return stuck
}

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

	cfg.clients = map[uint32]*ClientInfo{}

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

		cfg.SetSshClient(id, client)

		log.Printf("Connected to the server: client-%d -> %s \n", id, cfg.SshIp)
		defer func() {
			cfg.DeleteSshClient(id)
			client.Close()
			log.Printf("Disconnected to the server: client-%d -> %s \n", id, cfg.SshIp)
		}()

		to := time.NewTicker(time.Duration(cfg.Interval) * time.Second)
		defer to.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Printf("stopping ssh: id=%d, %v\n", id, ctx.Err())
				return
			case <-to.C:
				if err1 := run_cmd(ctx, id, client, cfg); err != nil {
					log.Printf("%v\n", err1)
					return
				}
			}
		}
	}

	for i := uint32(1); i <= cfg.NumClients; i++ {
		wg.Add(1)
		go sshCmd(i)
	}

	log.Printf("Waiting for stoppting all ssh clients...\n")
	<-ctx.Done()

	time.Sleep(time.Second)
	stuck := cfg.Clean()

	wg.Wait()

	if len(stuck) > 0 {
		log.Printf("stuck Count: %d \n", len(stuck))
		for _, s := range stuck {
			log.Printf("%s\n", s)
		}
	}

	log.Printf("Stopped all ssh clients\n")

	return nil
}
