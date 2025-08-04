package main

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"io"
	"iter"
	"net"
)

func dbg(format string, a ...any) {
	// fmt.Printf("DEBUG: "+format+"\n", a...)
}

func compressFlate(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return nil, err
	}
	_, err = writer.Write(data)
	if err != nil {
		return nil, err
	}
	writer.Close()
	return buf.Bytes(), nil
}

func decompressFlate(compressedData []byte) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(compressedData))
	defer reader.Close()

	decompressedData, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	return decompressedData, nil
}

func chunkize(data []byte) iter.Seq[uint32] {
	return func(yield func(uint32) bool) {
		for i := 0; i < len(data); i += DATA_SIZE_BYTES {
			end := min(i+DATA_SIZE_BYTES, len(data))

			chunk := data[i:end]
			if len(chunk) == 1 {
				chunk = append(chunk, 0x00)
			}
			data := binary.LittleEndian.Uint16(chunk)
			if !yield(uint32(data)) {
				return
			}
		}
	}
}

func collectChunks(packets []*IPv6Header) []byte {
	buffer := []byte{}

	for _, p := range packets {
		d := p.FlowLabel
		temp := make([]byte, 2)
		binary.LittleEndian.PutUint16(temp, uint16(d))
		buffer = append(buffer, temp[0:DATA_SIZE_BYTES]...)
	}

	return buffer
}

func decodeMessage(packets []*IPv6Header) (string, error) {
	buffer := collectChunks(packets)
	dec, err := decompressFlate(buffer)
	if err != nil {
		return "", fmt.Errorf("unable to decode message: %w", err)
	}

	return string(dec), nil
}

func getMyIpv6() (net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("unable to list interfaces: %w", err)
	}

	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if i.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}

		addrs, err := i.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// Skip nil or IPv4 addresses.
			if ip == nil || ip.To4() != nil {
				continue
			}

			// process IP address
			return ip, nil
		}
	}

	return nil, fmt.Errorf("unable to determine my ipv6")
}
