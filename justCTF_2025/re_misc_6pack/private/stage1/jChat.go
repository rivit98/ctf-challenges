package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type State int

const (
	StateDisconnected State = iota
	StateConnected

	StateSending
	StateReceiving
)

type App struct {
	state     State
	stateLock sync.Mutex

	transport *Transport
	cmdChan   chan Command
	netChan   chan *IPv6Header
}

func (a *App) help() {
	fmt.Println("available commands:")
	fmt.Println("!connect <client ipv6> - set peer ipv6 address")
	fmt.Println("text - sends the text to the peer")
	fmt.Println("!exit - and exits the program")
}

func (a *App) handleCommand(reader *bufio.Reader) (bool, error) {
	cmd, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("failed to read command: %w", err)
	}

	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return false, fmt.Errorf("empty command")
	}

	cmdParts := strings.SplitN(cmd, " ", 2)
	if len(cmdParts) == 0 {
		return false, fmt.Errorf("invalid command: %s", cmd)
	}

	switch cmdParts[0] {
	case "!connect":
		state := a.getState()
		if state == StateSending || state == StateReceiving {
			return false, fmt.Errorf("network communication pending")
		}

		if len(cmdParts) != 2 {
			return false, fmt.Errorf("invalid command: %s", cmd)
		}

		if state != StateDisconnected {
			return false, fmt.Errorf("already connected to the peer")
		}

		ipStr := cmdParts[1]
		dstAddr := net.ParseIP(ipStr)
		if dstAddr == nil {
			return false, fmt.Errorf("invalid destination IP address: %s", ipStr)
		}

		a.cmdChan <- &ConnectCommand{
			dstAddr: dstAddr,
		}
	case "!exit":
		return true, nil
	default:
		if a.getState() != StateConnected {
			return false, fmt.Errorf("not connected to the peer or network communication pending")
		}

		a.cmdChan <- &DataCommand{
			data: cmd,
		}
	}

	return false, nil
}

func (a *App) handleCommands() {
	reader := bufio.NewReaderSize(os.Stdin, 0x4000)

	for {
		stop, err := a.handleCommand(reader)
		if stop {
			close(a.cmdChan)
			break
		}
		if err != nil {
			fmt.Println(err)
		}
	}

	fmt.Println("exiting...")
}

func (a *App) close() error {
	return a.transport.Close()
}

func (a *App) setState(s State) {
	dbg("setState(%v)", s)
	a.stateLock.Lock()
	a.state = s
	a.stateLock.Unlock()
}

func (a *App) getState() State {
	a.stateLock.Lock()
	defer a.stateLock.Unlock()
	return a.state
}

func (a *App) start() {
	go a.handleCommands()
	go a.transport.HandleMessages()

	var timer *time.Timer
	chunks := []*IPv6Header{}
	reset := func() {
		a.setState(StateConnected)
		chunks = nil
		if timer != nil {
			timer.Stop()
		}
	}
	waiter := make(chan struct{})

	for {
		select {
		case cmd, ok := <-a.cmdChan:
			if !ok {
				dbg("handleChans: channel closed")
				return
			}

			dbg("handleChans: received command")

			nextState, err := cmd.Execute(a)
			a.setState(nextState)
			if err != nil {
				dbg("handleChans: unable to execute cmd: %v, %w", cmd, err)
				fmt.Println(err)
				continue
			}

			dbg("handleChans: cmd processing finished")

		case cmd, ok := <-a.netChan:
			if !ok {
				dbg("handleChans: channel closed")
				return
			}

			dbg("recved packet: %v", cmd) // remove

			// fiter out packets with different sourceIP than our dstAddr
			if !cmd.SourceIP.Equal(a.transport.dstAddr) {
				dbg("handleChans: mismatched ips - skipping the message")
				continue
			}

			switch a.getState() {
			case StateConnected:
				if cmd.FlowLabel != START {
					dbg("handleChans: not a START message")
					reset()
					continue
				}

				// start of the communication
				reset()
				a.setState(StateReceiving)

				fallthrough
			case StateReceiving:
				dbg("handleChans: sending ack")

				err := a.transport.Ack(cmd.FlowLabel)
				if err != nil {
					dbg("handleChans: unable to send ack: %w", err)
					reset()
					continue
				}

				dbg("handleChans: ack ok")

				if cmd.FlowLabel == STOP {
					dbg("handleChans: received STOP message")

					decoded, err := decodeMessage(chunks)
					if err != nil {
						dbg("handleChans: decode message failed: %v, %w", chunks, err)
						continue
					}

					fmt.Printf("> %s\n", decoded)
					reset()
				} else if cmd.FlowLabel != START {
					chunks = append(chunks, cmd)
				}
			case StateSending:
				payload := cmd.FlowLabel
				lastPayload := a.transport.last.FlowLabel
				if payload != lastPayload {
					dbg("handleChans: invalid ack received: %d vs %d", payload, lastPayload)
					reset()
					continue
				}
				dbg("handleChans: ack ok")
				if timer != nil {
					timer.Stop()
				}

				if a.transport.HasNext() {
					err := a.transport.Send()
					if err != nil {
						dbg("handleChans: %w", err)
						reset()
						continue
					}
					dbg("handleChans: sent packet")
					timer = time.AfterFunc(3*time.Second, func() {
						waiter <- struct{}{}
					})

				} else {
					dbg("handleChans: no more packets to send")
					reset()
				}
			}
		case <-waiter:
			dbg("handleChans: communication timed out")
			reset()
		}
	}
}

func newApp() (*App, error) {
	c := make(chan *IPv6Header)
	transport, err := NewTransport(c)
	if err != nil {
		return nil, err
	}

	a := &App{
		cmdChan:   make(chan Command),
		netChan:   c,
		transport: transport,
		state:     StateDisconnected,
	}

	return a, nil
}

func main() {
	app, err := newApp()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer app.close()

	app.help()
	app.start()
}
