package main

import (
	"encoding/binary"
	"math/rand/v2"
	"net"
)

const IPv6HeaderSize = 40

type IPv6Header struct {
	Version       uint8  // IPv6 version (4 bits)
	TrafficClass  uint8  // Traffic Class (8 bits)
	FlowLabel     uint32 // Flow Label (20 bits)
	PayloadLength uint16 // Length of the payload
	NextHeader    uint8  // Protocol (e.g., 58 for ICMPv6, 17 for UDP)
	HopLimit      uint8  // TTL equivalent
	SourceIP      net.IP // Source address (16 bytes)
	DestinationIP net.IP // Destination address (16 bytes)
}

func (h *IPv6Header) Serialize() []byte {
	buf := make([]byte, IPv6HeaderSize)
	versionTrafficFlow := (uint32(h.Version) << 28) | (uint32(h.TrafficClass) << 20) | (h.FlowLabel)
	binary.BigEndian.PutUint32(buf[:4], versionTrafficFlow)
	binary.BigEndian.PutUint16(buf[4:6], h.PayloadLength)
	buf[6] = h.NextHeader
	buf[7] = h.HopLimit
	copy(buf[8:24], h.SourceIP.To16())
	copy(buf[24:40], h.DestinationIP.To16())
	return buf
}

// DeserializeIPv6Header converts a byte slice to an IPv6Header struct
func DeserializeIPv6Header(buf []byte) *IPv6Header {
	version := buf[0] >> 4
	trafficClass := (buf[0]&0x0F)<<4 | (buf[1] >> 4)
	flowLabel := binary.BigEndian.Uint32(buf[:4]) & 0x000FFFFF

	payloadLength := binary.BigEndian.Uint16(buf[4:6])
	nextHeader := buf[6]
	hopLimit := buf[7]
	sourceIP := net.IP(buf[8:24])
	destinationIP := net.IP(buf[24:40])

	return &IPv6Header{
		Version:       version,
		TrafficClass:  trafficClass,
		FlowLabel:     flowLabel,
		PayloadLength: payloadLength,
		NextHeader:    nextHeader,
		HopLimit:      hopLimit,
		SourceIP:      sourceIP,
		DestinationIP: destinationIP,
	}
}

func NewIPv6Header(source, destination net.IP, data uint32) *IPv6Header {
	return &IPv6Header{
		Version:       6,                          // IPv6 version (6)
		TrafficClass:  uint8(rand.UintN(32)),      // Traffic Class (0)
		FlowLabel:     data,                       // Flow Label (0)
		PayloadLength: uint16(rand.UintN(0x1000)), // Payload Length (initially 0)
		NextHeader:    uint8(rand.UintN(64)),      // ICMPv6 (just as an example)
		HopLimit:      uint8(rand.UintN(32) + 10), // Default TTL
		SourceIP:      source,                     // Set source IP address
		DestinationIP: destination,                // Set destination IP address
	}
}

// func (h *IPv6Header) String() string {
// 	// return fmt.Sprintf("IPv6 Header\n"+
// 	// 	"  Version: %d\n"+
// 	// 	"  Traffic Class: %d\n"+
// 	// 	"  Flow Label: %d\n"+
// 	// 	"  Payload Length: %d\n"+
// 	// 	"  Next Header: %d\n"+
// 	// 	"  Hop Limit: %d\n"+
// 	// 	"  Source IP: %s\n"+
// 	// 	"  Destination IP: %s\n",
// 	// 	h.Version, h.TrafficClass, h.FlowLabel, h.PayloadLength,
// 	// 	h.NextHeader, h.HopLimit, h.SourceIP, h.DestinationIP)

// 	return fmt.Sprintf("IPv6 Header\n"+
// 		"  Flow Label: %d\n"+
// 		"  Source IP: %s\n"+
// 		"  Destination IP: %s\n",
// 		h.FlowLabel, h.SourceIP, h.DestinationIP)
// }
