package main

import (
	"net"
)

type Command interface {
	Execute(app *App) (State, error)
}

type ConnectCommand struct {
	dstAddr net.IP
}

func (c *ConnectCommand) Execute(app *App) (State, error) {
	app.transport.Connect(c.dstAddr)
	return StateConnected, nil
}

type DataCommand struct {
	data string
}

func (c *DataCommand) Execute(app *App) (State, error) {
	err := app.transport.EnqueuePackets([]byte(c.data))
	if err != nil {
		return StateConnected, err
	}

	// send first packet
	err = app.transport.Send()
	if err != nil {
		return StateConnected, err
	}

	return StateSending, nil
}
