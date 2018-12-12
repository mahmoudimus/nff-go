// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package lb

import (
	"fmt"

	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

func balancer(pkt *packet.Packet, ctx flow.UserContext) bool {
	pkt.ParseL3()
	originalProtocol := pkt.Ether.EtherType

	// Check packet protocol number
	if originalProtocol == common.SwapARPNumber {
		err := LBConfig.InputPort.neighCache.HandleIPv4ARPPacket(pkt)
		if err != nil {
			fmt.Println(err)
		}
		return false
	} else if originalProtocol == common.SwapIPV4Number {
		ipv4 := pkt.GetIPv4NoCheck()
		if !LBConfig.TunnelSubnet.IPv4.CheckIPv4AddressWithinSubnet(ipv4.DstAddr) {
			fmt.Println("Received IPv4 packet that is not targeted at balanced subnet",
				LBConfig.TunnelPort.Subnet.IPv4.String(),
				"it is targeted at address", ipv4.DstAddr.String(), "instead. Packet dropped.")
			return false
		}
	} else if originalProtocol == common.SwapIPV6Number {
		ipv6 := pkt.GetIPv6NoCheck()
		if !LBConfig.TunnelSubnet.IPv6.CheckIPv6AddressWithinSubnet(ipv6.DstAddr) {
			fmt.Println("Received IPv6 packet that is not targeted at balanced subnet",
				LBConfig.TunnelPort.Subnet.IPv6.String(),
				"it is targeted at address", ipv6.DstAddr.String(), "instead. Packet dropped.")
			return false
		}
	} else {
		return false
	}

	worker := findWorkerIndex(pkt)
	workerIP := LBConfig.WorkerAddresses[worker]
	workerMAC, found := LBConfig.TunnelPort.neighCache.LookupMACForIPv4(workerIP)
	if !found {
		fmt.Println("Not found MAC address for IP", workerIP.String())
		LBConfig.TunnelPort.neighCache.SendARPRequestForIPv4(workerIP, 0)
		return false
	}

	if !pkt.EncapsulateHead(common.EtherLen, common.IPv4MinLen+common.GRELen) {
		fmt.Println("EncapsulateHead returned error")
		return false
	}
	pkt.ParseL3()

	// Fill up L2
	pkt.Ether.SAddr = LBConfig.TunnelPort.macAddress
	pkt.Ether.DAddr = workerMAC
	pkt.Ether.EtherType = common.SwapIPV4Number

	// Fill up L3
	ipv4 := pkt.GetIPv4NoCheck()
	length := pkt.GetPacketLen()

	// construct iphdr
	ipv4.VersionIhl = 0x45
	ipv4.TypeOfService = 0
	ipv4.PacketID = 0x1513
	ipv4.FragmentOffset = 0
	ipv4.TimeToLive = 64

	ipv4.TotalLength = packet.SwapBytesUint16(uint16(length - common.EtherLen))
	ipv4.NextProtoID = common.GRENumber
	ipv4.SrcAddr = LBConfig.TunnelPort.Subnet.IPv4.Addr
	ipv4.DstAddr = workerIP
	ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))

	// Fill up L4
	pkt.ParseL4ForIPv4()
	gre := pkt.GetGREForIPv4()
	gre.Flags = 0
	gre.NextProto = originalProtocol

	return true
}

func findWorkerIndex(pkt *packet.Packet) int {
	return 0
}
