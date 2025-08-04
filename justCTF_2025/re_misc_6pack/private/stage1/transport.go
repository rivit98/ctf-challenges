package main

import (
	"errors"
	"fmt"
	"net"
)

const DATA_SIZE_BITS = 16
const DATA_SIZE_BYTES = 2

const START = 1 << DATA_SIZE_BITS
const STOP = 1<<DATA_SIZE_BITS | 1

type Transport struct {
	conn    *net.IPConn
	srcIp   net.IP
	dstAddr net.IP
	netchan chan *IPv6Header
	sendQ   []*IPv6Header

	last *IPv6Header
}

func NewTransport(publishChan chan *IPv6Header) (*Transport, error) {
	ip, err := getMyIpv6()
	if err != nil {
		return nil, fmt.Errorf("cannot get my ip: %w", err)
	}

	ln, err := net.ListenIP("ip6:ipv6", &net.IPAddr{IP: ip})
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}

	return &Transport{
		conn:    ln,
		srcIp:   ip,
		netchan: publishChan,
	}, nil
}

func (t *Transport) sendPacket(packet *IPv6Header) error {
	_, err := t.conn.WriteTo(packet.Serialize(), &net.IPAddr{IP: packet.DestinationIP})
	if err != nil {
		return fmt.Errorf("failed to send packet: %w", err)
	}

	return nil
}

func (t *Transport) EnqueuePackets(data []byte) error {
	t.clearSndQ()

	compressed, err := compressFlate(data)
	if err != nil {
		return fmt.Errorf("failed to compress data: %w", err)
	}

	t.sendQ = append(t.sendQ, NewIPv6Header(t.srcIp, t.dstAddr, START))
	for data := range chunkize(compressed) {
		p := NewIPv6Header(t.srcIp, t.dstAddr, data)
		t.sendQ = append(t.sendQ, p)
	}
	t.sendQ = append(t.sendQ, NewIPv6Header(t.srcIp, t.dstAddr, STOP))

	return nil
}

func (t *Transport) Send() error {
	var p *IPv6Header
	p, t.sendQ = t.sendQ[0], t.sendQ[1:]
	err := t.sendPacket(p)
	t.last = p
	return err
}

func (t *Transport) HasNext() bool {
	return len(t.sendQ) > 0
}

func (t *Transport) clearSndQ() {
	t.sendQ = nil
}

func (t *Transport) Ack(val uint32) error {
	p := NewIPv6Header(t.srcIp, t.dstAddr, val)
	return t.sendPacket(p)
}

func (t *Transport) HandleMessages() {
	buf := make([]byte, 1500)

	for {
		n, _, err := t.conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				dbg("network connection closed")
				close(t.netchan)
				break
			}

			dbg("Error reading packet: %v", err)
			continue
		}

		if n != IPv6HeaderSize {
			dbg("Packet too short for an IPv6 header")
			continue
		}

		t.netchan <- DeserializeIPv6Header(buf)
	}
}

func (t *Transport) Close() error {
	err := t.conn.Close()
	if err != nil {
		return fmt.Errorf("failed to close connection: %w", err)
	}
	return nil
}

func (t *Transport) Connect(dst net.IP) {
	t.dstAddr = dst
}

func (t *Transport) Disconnect() {
	t.dstAddr = nil
}
