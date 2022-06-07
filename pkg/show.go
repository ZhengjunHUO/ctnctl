package pkg

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
	"strconv"
	"errors"

	"github.com/cilium/ebpf"
	"github.com/ZhengjunHUO/ctnctl/tools"
)

/*
Bitmap: 8 bits
  00000000
       |||- isIngress
       ||-- isBannedL3
       |--- isBannedL4
*/
type entry struct {
	Saddr	uint32
	Daddr	uint32
	Sport	uint16
	Dport	uint16
	Proto	uint8
	Bitmap	uint8
}

type socket struct {
	Addr	 uint32
	Port	 uint16
	Reserved uint16
}

// Show all rules related to container
func PrintFirewall(name string) {
	// Get container's full ID
	cgroupId := GetContainerID(name)
	if len(cgroupId) == 0 {
		fmt.Println("Invalid container name or id!")
	}

	// Check if dir exist
	pinPath := bpfPath + cgroupId
	if _, err := os.Stat(pinPath); err != nil {
		// no ebpf rules
		return
	}

	// load pinned firewalls
	egressMapPinPath := pinPath + "/egs_map"
	ingressMapPinPath := pinPath + "/igs_map"
	egressL4MapPinPath := pinPath + "/egs_l4_map"
	ingressL4MapPinPath := pinPath + "/igs_l4_map"

	emap, err := ebpf.LoadPinnedMap(egressMapPinPath, nil)
	if err != nil {
		return
	}

	imap, err := ebpf.LoadPinnedMap(ingressMapPinPath, nil)
	if err != nil {
		return
	}

	emapL4, err := ebpf.LoadPinnedMap(egressL4MapPinPath, nil)
	if err != nil {
		return
	}

	imapL4, err := ebpf.LoadPinnedMap(ingressL4MapPinPath, nil)
	if err != nil {
		return
	}

	var (
		key uint32
		value bool
		skt socket
	)

	// Dump all the ingress/egress rules from maps
	fmt.Println("Blocked egress L3 [To]:")
	entries := emap.Iterate()
	for entries.Next(&key, &value) {
		fmt.Printf("\t%s\n", tools.Uint32ToIPv4(key))
	}

	fmt.Println("Blocked egress L4 [To]:")
	entries = emapL4.Iterate()
	for entries.Next(&skt, &value) {
		fmt.Printf("\t%s:%v\n", tools.Uint32ToIPv4(skt.Addr), tools.Uint16ToPort(skt.Port))
	}

	fmt.Println("\nBlocked ingress L3 [From]:")
	entries = imap.Iterate()
	for entries.Next(&key, &value) {
		fmt.Printf("\t%s\n", tools.Uint32ToIPv4(key))
	}

	fmt.Println("\nBlocked ingress L4 [From]:")
	entries = imapL4.Iterate()
	for entries.Next(&skt, &value) {
		fmt.Printf("\t%s:%v\n", tools.Uint32ToIPv4(skt.Addr), tools.Uint16ToPort(skt.Port))
	}
}

// Follow packet flows associated to container
func PrintDataflow(name string) error {
	// Get container's full ID
	cgroupId := GetContainerID(name)
	if len(cgroupId) == 0 {
		return errors.New("Invalid container name or id!\n")
	}

	// Check if dir exist
	pinPath := bpfPath + cgroupId
	if _, err := os.Stat(pinPath); err != nil {
		// dir not exist
		return err
	}

	dataflowPinPath := pinPath + "/dataflow_map"

	// restore data flow map from pinned file on bpffs
	fl, err := ebpf.LoadPinnedMap(dataflowPinPath, nil)
	if err != nil {
		return err
	}

	fmt.Println("Tracking ... press Ctrl + c to quit")
	// check the map at regular intervals
	tkr := time.NewTicker(time.Second)

	// capture sigint and sigterm
	chInt := make(chan os.Signal, 1)
	signal.Notify(chInt, os.Interrupt, syscall.SIGTERM)

	// protocol number to name mapping 
	protocols := map[uint8]string{1: "ICMP", 6: "TCP", 17: "UDP"}

	var ent entry
	var saddr, daddr, protocolName, entlog string
	var isIngress, isBannedL3, isBannedL4 bool

	loop: for {
		select {
			case <- tkr.C:
				// retrieve all the entries from the map
				for fl.LookupAndDelete(nil, &ent) == nil {
					saddr, daddr = tools.Uint32ToIPv4(ent.Saddr), tools.Uint32ToIPv4(ent.Daddr)
					isIngress, isBannedL3, isBannedL4 = (ent.Bitmap & 1) == 1, ((ent.Bitmap & 2) >> 1) == 1, ((ent.Bitmap & 4) >> 2) == 1

					// identify the protocol name
					if val, ok := protocols[ent.Proto]; ok {
						protocolName = val
					}else{
						protocolName = strconv.Itoa(int(ent.Proto))
					}

					sport, dport := tools.Uint16ToPort(ent.Sport), tools.Uint16ToPort(ent.Dport)

					// prepare the log to print
					if isIngress {
						if ent.Proto == 1 {
							entlog = fmt.Sprintf("%s IN %s > %s", protocolName, saddr, daddr)
						}else{
							entlog = fmt.Sprintf("%s IN %s:%v > %s:%v", protocolName, saddr, sport, daddr, dport)
						}
					}else{
						if ent.Proto == 1 {
							entlog = fmt.Sprintf("%s OUT %s > %s", protocolName, saddr, daddr)
						}else{
							entlog = fmt.Sprintf("%s OUT %s:%v > %s:%v", protocolName, saddr, sport, daddr, dport)
						}
					}

					// update the log if the packet is banned
					if isBannedL3 {
						entlog += " (BANNED L3)"
					}

					if isBannedL4 {
						entlog += " (BANNED L4)"
					}

					fmt.Println(entlog)
				}
			case <- chInt:
				// quit on capturing the sigint, sigterm
				break loop
		}
	}

	fmt.Println("Tracking stopped.")
	return nil
}
