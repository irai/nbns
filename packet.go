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

/******
type nodeStatusPacket struct {
	TrnId      uint16 // Transaction ID for Name Service Transaction. Requestor places a unique value for each active transaction.
	Response   uint16
	Opcode     uint16 // Packet type code, see table below.
	NMFlags    uint16 // Flags for operation, see table below.
	Rcode      uint16 // Result codes of request.  Table of Rcode values for each response packet below.
	QDCount    uint16 // the number of entries in the question section of a Name
	ANCount    uint16 // number of resource records in the answer section of a Name Service packet.
	NSCount    uint16 //number of resource records in the authority section of a Name Service packet.
	ARCount    uint16 //number of resource records in the additional records section of a Name Service packet.
	QName      string
	QType      uint16
	QClass     uint16
	RRName     string
	RRType     uint16
	RRClass    uint16
	Fill       uint32
	RDLen      uint16
	NumNames   uint8
	NodeNames  []string
	Statistics []byte
}

func newNBNSNameQuery(netbiosName string) (r *nodeStatusPacket) {
	r = new(nodeStatusPacket)

	r.TrnId = 0x11
	r.Opcode = opcodeQuery
	r.NMFlags = 0x00
	r.Response = responseRequest
	r.Rcode = 0
	r.QDCount = 1

	r.QType = questionTypeNodeStatus
	r.QClass = questionClassInternet
	r.QName = encodeNBNSName(netbiosName)
	//fmt.Println("qname -->", r.QName)

	return r
}
****/

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

func decodeNBNSName(buffer []byte) (name string) {
	// Get the first name.
	if len(buffer) < netbiosMaxNameLen*2+2 && buffer[netbiosMaxNameLen*2+1] != 0x00 {
		log.Error("nbns invalid name in packet ", len(buffer), buffer[netbiosMaxNameLen*2+1])
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
	if buffer[0] != 0x20 {
		log.Error("nbns unexpected name len in nbns packet", buffer[0])
		return ""
	}

	// 0 is len; name starts at 1
	for i := 1; i < 0x21; i = i + 2 {
		character := ((buffer[i] - 'A') << 4) | (buffer[i+1] - 'A')
		name = name + string(character)
	}

	return name
}

/**
// ToWireFormat creates the byte stream ready to be sent on the wire.
//
func (r *nodeStatusPacket) ToWireFormat(buf *bytes.Buffer) error {

	// var word uint16 = r.Response | r.Opcode | r.NMFlags | r.Rcode
	var word = r.Response | r.Opcode | r.NMFlags | r.Rcode

	binary.Write(buf, binary.BigEndian, r.TrnId)
	binary.Write(buf, binary.BigEndian, uint16(word))
	binary.Write(buf, binary.BigEndian, r.QDCount)
	binary.Write(buf, binary.BigEndian, r.ANCount)
	binary.Write(buf, binary.BigEndian, r.NSCount)
	binary.Write(buf, binary.BigEndian, r.ARCount)

	binary.Write(buf, binary.BigEndian, []byte(r.QName))
	binary.Write(buf, binary.BigEndian, r.QType)
	binary.Write(buf, binary.BigEndian, r.QClass)

	return nil
}

func fromWireFormat(buffer *bytes.Buffer) (hdr *nodeStatusPacket) {
	var word uint16

	hdr = new(nodeStatusPacket)
	log.Debugf("NBNS trnid %2x ", packet(buffer.Bytes()).trnID())
	binary.Read(buffer, binary.BigEndian, &hdr.TrnId)
	binary.Read(buffer, binary.BigEndian, &word)
	hdr.Response = word & responseMASK
	hdr.Opcode = word & opcodeMASK
	hdr.NMFlags = word & nmflagsMASK
	hdr.Rcode = word & rcodeMASK
	binary.Read(buffer, binary.BigEndian, &hdr.QDCount)
	binary.Read(buffer, binary.BigEndian, &hdr.ANCount)
	binary.Read(buffer, binary.BigEndian, &hdr.NSCount)
	binary.Read(buffer, binary.BigEndian, &hdr.ARCount)

	log.Debug("NBNS parsed header")
	log.Debugf("NBNS trnid %2x  mask %16b", hdr.TrnId, word)
	log.Debugf("NBNS QDCount %2x  ANCount %2x \n", hdr.QDCount, hdr.ANCount)
	log.Debugf("NBNS NSCount %2x  ARCount %2x \n", hdr.NSCount, hdr.ARCount)

	// Assume a single Question name
	if hdr.QDCount > 0 {
		hdr.QName = parseNBSName(buffer)
		binary.Read(buffer, binary.BigEndian, &hdr.QType)
		binary.Read(buffer, binary.BigEndian, &hdr.QClass)
		log.Debugf("NBNS QName %s  QType %2x QClass %2x\n", hdr.QName, hdr.QType, hdr.QClass)
	}

	// Assume a single Response name
	if hdr.ANCount > 0 {
		hdr.RRName = parseNBSName(buffer)
		binary.Read(buffer, binary.BigEndian, &hdr.RRType)
		binary.Read(buffer, binary.BigEndian, &hdr.RRClass)
		log.Debugf("NBNS RRName %s  RRType %2x RRClass %2x\n", hdr.RRName, hdr.RRType, hdr.RRClass)
	}

	switch hdr.RRType {
	case questionTypeNodeStatus:
		binary.Read(buffer, binary.BigEndian, &hdr.Fill)
		binary.Read(buffer, binary.BigEndian, &hdr.RDLen)
		binary.Read(buffer, binary.BigEndian, &hdr.NumNames)

		log.Debugf("NBNS RDLen %2x RRClass %2x\n", hdr.RDLen, hdr.NumNames)

		tmp := make([]byte, 16)

		for i := 0; i < int(hdr.NumNames); i++ {
			var nameFlags uint16
			binary.Read(buffer, binary.BigEndian, &tmp)
			binary.Read(buffer, binary.BigEndian, &nameFlags)
			log.Info("name ", tmp, len(tmp))
			t := strings.TrimRight(string(tmp), "\x00")
			log.Info("name00 ", t, len(t))
			t = strings.Trim(t, " ")
			log.Info("namenospace ", t, len(t))
			hdr.NodeNames = append(hdr.NodeNames, t)
			log.Debugf("NBNS NodeName %q nameFlags %2x\n", t, nameFlags)

		}
	}
	return hdr

}
	***/

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
	// Examples Netbios name encoding
	// Lenght = 16 bytes when converted become 32 bytes + len(1) + end(1)
	// "FRED            "
	// Hexa: 0x20 EG FC EF EE CA CA CA CA CA CA CA CA CA CA CA CA 0x00
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
