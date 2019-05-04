package nbns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	netbiosMaxNameLen = 16
	//     1   1   1   1   1   1
	//     5   4   3   2   1   0   9   8   7   6   5   4   3   2   1   0
	//   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	//   | R |    Opcode     |AA |TC |RD |RA | 0 | 0 | B |     Rcode     |
	//   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

	// response flag: bit 15
	responseMASK     = 0x01 << 15
	responseRequest  = 0x00 << 15
	responseresponse = 0x10 << 15

	// Opcode: bits 11,12,13,14
	opcodeMASK         = 0x0f << 11
	opcodeQuery        = 0 << 11
	opcodeRegistration = 5 << 11
	opcodeRelease      = 6 << 11
	opcodeWack         = 7 << 11
	opcodeRefresh      = 8 << 11

	// NbnsFlags: bits 4, 5, 6, 7, 8, 9, 10
	nmflagsMASK                = 0x7f << 4
	nmflagsUnicast             = 0x00 << 4
	nmflagsBroadcast           = 0x01 << 4
	nmflagsRecursionAvailable  = 0x08 << 4
	nmflagsRecursionDesired    = 0x10 << 4
	nmflagsTruncated           = 0x20 << 4
	nmflagsAuthoritativeAnswer = 0x40 << 4

	// Rcode: bits 0, 1, 2, 3
	rcodeMASK   = 0x0f
	rcodeOK     = 0x0
	rcodeFMTErr = 0x1 //Format Error.  Request was invalidly formatted.
	rcodeSRVErr = 0x2 // Server failure.  Problem with NBNS, cannot process name.
	rcodeIMPErr = 0x4 // Unsupported request error.
	rcodeRFSErr = 0x5 // Refused error.  For policy reasons server will not register this name from this host.
	rcodeACTErr = 0x6 // Active error.  Name is owned by another node.
	rcodeCFTErr = 0x7 // Name in conflict error.  A UNIQUE name is owned by more than one node.

	// NbnsQuestionType
	questionTypeGeneral    = 0x0020 //  NetBIOS general Name Service Resource Record
	questionTypeNodeStatus = 0x0021 // NBSTAT NetBIOS NODE STATUS Resource Record (See NODE STATUS REQUEST)

	// NbnsQuestionClass
	questionClassInternet = 0x0001
)

var sequence uint16 = 1

// encodeNBNSName creates a 34 byte string = 1 char length + 32 char netbios name + 1 final length (0x00).
//                   Netbios names are 16 bytes long = 15 characters plus space(0x20)
//
//
func encodeNBNSName(name string) string {

	// Netbios name is limited to 15 characters long
	if len(name) > netbiosMaxNameLen {
		name = name[:netbiosMaxNameLen] // truncate if name too long
	}

	if len(name) < netbiosMaxNameLen {
		name = name + strings.Repeat(" ", netbiosMaxNameLen-len(name))
	}
	buffer := bytes.Buffer{}

	// Name len = 16 * 2 bytes format
	buffer.Write([]byte{netbiosMaxNameLen * 2})

	for i := range name {
		var store [2]byte
		store[0] = 'A' + (name[i] >> 4)
		store[1] = 'A' + (name[i] & 0x0f)
		buffer.Write(store[:])
	}

	// Final name - len 0x00 means no more names
	buffer.Write([]byte{0x00})

	log.Debugf("NBNS netbios len %v name ->%s\n", len(buffer.Bytes()), string(buffer.Bytes()))

	return string(buffer.Bytes())
}

func decodeNBNSName(buf *bytes.Buffer) (name string) {
	// Get the first name.
	tmp := make([]byte, netbiosMaxNameLen*2+2)
	err := binary.Read(buf, binary.BigEndian, &tmp)
	if err != nil || tmp[len(tmp)-1] != 0x00 {
		log.Error("nbns invalid name in packet ", len(buf.Bytes()), buf)
		return ""
	}

	//	fmt.Printf("RR name len %v name % x \n", length, name)

	// A label length count is actually a 6-bit field in the label length
	// field.  The most significant 2 bits of the field, bits 7 and 6, are
	// flags allowing an escape from the above compressed representation.
	// Note that the first octet of a compressed name must contain one of
	// the following bit patterns.  (An "x" indicates a bit whose value may
	// be either 0 or 1.):
	//
	//    00100000 -  Netbios name, length must be 32 (decimal) (0x20)
	//    11xxxxxx -  Label string pointer
	//    10xxxxxx -  Reserved
	//    01xxxxxx -  Reserved
	if tmp[0] != 0x20 {
		log.Error("nbns unexpected name len in nbns packet", tmp[0])
		return ""
	}

	// 0 is len; name starts at 1
	tmp = tmp[1:]
	for i := 0; i < 32; i = i + 2 {
		character := ((tmp[i] - 'A') << 4) | (tmp[i+1] - 'A')
		name = name + string(character)
	}

	return strings.TrimRight(name, " ")
}

//     Bits
//     0   1   2    3  4   5   6   7   0   2   2   3   4   5   6   7
//   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//   | R |    Opcode     |AA |TC |RD |RA | 0 | 0 | B |     Rcode     |
//   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// Work in progress - TBD
type packet []byte

func (p packet) response() byte       { return p[2] >> 7 }
func (p packet) opcode() byte         { return (p[2] & 0x70) >> 3 }
func (p packet) flagsBroadcast() byte { return (p[3] & 0x10) >> 4 }
func (p packet) rcode() byte          { return p[3] & 0x0f }

// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         NAME_TRN_ID           | OPCODE  |   NM_FLAGS  | RCODE |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          QDCOUNT              |           ANCOUNT             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          NSCOUNT              |           ARCOUNT             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

func (p packet) trnID() uint16   { return uint16(p[0])<<8 | uint16(p[1]) }
func (p packet) flags() uint16   { return uint16(p[2])<<8 | uint16(p[3]) }
func (p packet) qdCount() uint16 { return uint16(p[4])<<8 | uint16(p[5]) }
func (p packet) anCount() uint16 { return uint16(p[6])<<8 | uint16(p[7]) }
func (p packet) nsCount() uint16 { return uint16(p[8])<<8 | uint16(p[9]) }
func (p packet) arCount() uint16 { return uint16(p[10])<<8 | uint16(p[11]) }
func (p packet) payload() []byte { return p[12:] }

func (p packet) printHeader() {
	fmt.Println("NBNS packet structure")
	// fmt.Printf("Buffer: 0x%02q\n", p)
	fmt.Printf("TrnId 0x%04x\n", p.trnID())
	fmt.Printf("response %b\n", p.response())
	fmt.Printf("opcode %b\n", p.opcode())
	fmt.Printf("flags %016b\n", p.flags())
	fmt.Printf("  broadcast %v\n", p.flagsBroadcast())
	fmt.Printf("rcode %b\n", p.rcode())
	fmt.Printf("QDCount 0x%04x | ANCount 0x%04x\n", p.qdCount(), p.anCount())
	fmt.Printf("NSCount 0x%04x | ARCount 0x%04x\n", p.nsCount(), p.arCount())
}

// Node Status Request - Packet layout must be packed with bigendian
//
//                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |         NAME_TRN_ID           |0|  0x0  |0|0|0|0|0 0|B|  0x0  |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  QDCOUNT 0x0001               | ANCOUNT   0x0000              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  NSCOUNT 0x0000               | ARCOUNT   0x0000              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   /                         QUESTION_NAME                         /
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |         NBSTAT (0x0020)       |        IN (0x0001)            |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func nameQueryWireFormat(name string) (packet packet) {
	return query(name, questionTypeGeneral)
}

// same as name query but type 21
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |         NBSTAT (0x0021)       |        IN (0x0001)            |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func nodeStatusRequestWireFormat(name string) (packet packet) {
	return query(name, questionTypeNodeStatus)
}

func query(name string, questionType uint16) (packet packet) {
	const word = uint16(responseRequest | opcodeQuery | nmflagsBroadcast | rcodeOK)

	// Write variable len byte sequence
	buf := new(bytes.Buffer)
	sequence++
	binary.Write(buf, binary.BigEndian, uint16(sequence)) // TrnID
	binary.Write(buf, binary.BigEndian, uint16(word))
	binary.Write(buf, binary.BigEndian, uint16(1)) // QDCount
	binary.Write(buf, binary.BigEndian, uint16(0)) // ANCount
	binary.Write(buf, binary.BigEndian, uint16(0)) // NSCount
	binary.Write(buf, binary.BigEndian, uint16(0)) // ARCount

	binary.Write(buf, binary.BigEndian, []byte(encodeNBNSName(name)))
	binary.Write(buf, binary.BigEndian, uint16(questionType))          // Qtype
	binary.Write(buf, binary.BigEndian, uint16(questionClassInternet)) // QClass
	return buf.Bytes()
}
