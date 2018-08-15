// Copyright 2017-2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nat

import (
	"fmt"
	"log"
	"os"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/packet"
)

func (t *Tuple) String() string {
	return fmt.Sprintf("addr = %d.%d.%d.%d:%d",
		(t.addr>>24)&0xff,
		(t.addr>>16)&0xff,
		(t.addr>>8)&0xff,
		t.addr&0xff,
		t.port)
}

func StringIPv4Int(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(addr>>24)&0xff,
		(addr>>16)&0xff,
		(addr>>8)&0xff,
		addr&0xff)
}

func StringIPv4Array(addr [common.IPv4AddrLen]uint8) string {
	return fmt.Sprintf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3])
}

func StringMAC(mac [common.EtherAddrLen]uint8) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func swapAddrIPv4(pkt *packet.Packet) {
	ipv4 := pkt.GetIPv4NoCheck()

	pkt.Ether.SAddr, pkt.Ether.DAddr = pkt.Ether.DAddr, pkt.Ether.SAddr
	ipv4.SrcAddr, ipv4.DstAddr = ipv4.DstAddr, ipv4.SrcAddr
}

func (port *ipv4Port) startTrace(dir uint) *os.File {
	dumpNameLookup := [dirKNI + 1]string{
		"drop",
		"dump",
		"kni",
	}

	fname := fmt.Sprintf("%s-%d-%s.pcap", dumpNameLookup[dir], port.Index, packet.MACToString(port.SrcMACAddress))

	file, err := os.Create(fname)
	if err != nil {
		log.Fatal(err)
	}
	packet.WritePcapGlobalHdr(file)
	return file
}

func (port *ipv4Port) dumpPacket(pkt *packet.Packet, dir uint) {
	if debugDump {
		port.dumpsync[dir].Lock()
		if port.fdump[dir] == nil {
			port.fdump[dir] = port.startTrace(dir)
		}

		err := pkt.WritePcapOnePacket(port.fdump[dir])
		if err != nil {
			log.Fatal(err)
		}
		port.dumpsync[dir].Unlock()
	}
}

func (port *ipv4Port) closePortTraces() {
	for _, f := range port.fdump {
		if f != nil {
			f.Close()
		}
	}
}

// CloseAllDumpFiles closes all debug dump files.
func CloseAllDumpFiles() {
	for i := range Natconfig.PortPairs {
		Natconfig.PortPairs[i].PrivatePort.closePortTraces()
		Natconfig.PortPairs[i].PublicPort.closePortTraces()
	}
}
