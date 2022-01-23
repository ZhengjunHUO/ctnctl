package tools

import (
	"encoding/binary"
	"net"
)

// translate ipv4 address in skb (uint32) to string (eg. 1.2.3.4)
func Uint32ToIPv4(n uint32) string {
	var buffer [4]byte
	binary.LittleEndian.PutUint32(buffer[:], n)

	return net.IPv4(buffer[0], buffer[1], buffer[2], buffer[3]).String()
}

// parse a ipv4 address in format string to a uint32 
func Ipv4ToUint32(s string) uint32 {
	return binary.LittleEndian.Uint32(net.ParseIP(s).To4())
}

func Uint16ToPort(n uint16) uint16 {
	var port [2]byte
	binary.LittleEndian.PutUint16(port[:], n)
	return binary.BigEndian.Uint16(port[:])
}
