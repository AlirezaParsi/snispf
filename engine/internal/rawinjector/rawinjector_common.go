package rawinjector

import "encoding/binary"

const ipProtoTCP = 6

func equal4(a, b []byte) bool {
	return len(a) >= 4 && len(b) >= 4 && a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3]
}

func ipHeaderLen(ip []byte) int {
	return int(ip[0]&0x0f) * 4
}

func checksumFold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func sum16(data []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	return sum
}

func ipChecksum(iph []byte) uint16 {
	return checksumFold(sum16(iph))
}

func tcpChecksum(iph []byte, tcpPayload []byte) uint16 {
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], iph[12:16])
	copy(pseudo[4:8], iph[16:20])
	pseudo[9] = ipProtoTCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcpPayload)))
	return checksumFold(sum16(pseudo) + sum16(tcpPayload))
}
