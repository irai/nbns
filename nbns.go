package nbns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
)

// Handler create a new NBNS handler
type Handler struct {
	conn         *net.UDPConn
	notification chan<- Entry
}

// Entry holds a NBNS name entry
type Entry struct {
	IP   net.IP
	Name string
}

// NewHandler create a NBNS handler
func NewHandler() (handler *Handler, err error) {
	// srcAddr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")

	handler = &Handler{}
	if handler.conn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: nil, Port: 137}); err != nil {
		log.Error("NBNS failed to bind UDP port 137 ", err)
		return nil, err
	}
	return handler, nil

}

// SendQuery send a NBNS query
// 4.2.12.  NAME QUERY REQUEST
//
//                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         NAME_TRN_ID           |0|  0x0  |0|0|1|0|0 0|B|  0x0  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          0x0001               |           0x0000              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          0x0000               |           0x0000              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// /                         QUESTION_NAME                         /
// /                                                               /
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           NB (0x0020)         |        IN (0x0001)            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func (h *Handler) SendQuery(ip net.IP) (err error) {

	packet := nodeStatusRequestWireFormat(`*               `)
	packet.printHeader()

	if ip == nil || ip.Equal(net.IPv4zero) {
		return fmt.Errorf("invalid IP nil %v", ip)
	}
	// ip[3] = 255 // Network broadcast

	// To broadcast, use network broadcast i.e 192.168.0.255 for example.
	targetAddr := &net.UDPAddr{IP: ip, Port: 137}
	if _, err = h.conn.WriteToUDP(packet, targetAddr); err != nil {
		log.Error("NPNS failed to send nbns packet ", err)
		return err
	}
	return nil
}

// AddNotificationChannel set the notification channel for new names
func (h *Handler) AddNotificationChannel(notification chan<- Entry) {
	h.notification = notification
}

// Stop all goroutines
func (h *Handler) Stop() {
	h.conn.Close()
	GoroutinePool.Stop() // will stop all goroutines
}

// processNodeStatusResponse
// 4.2.18.  NODE STATUS RESPONSE
//                           1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |         Header                                                |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   /                            RR_NAME (variable len)             /
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |        NBSTAT (0x0021)        |         IN (0x0001)           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                          0x00000000                           |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |          RDLENGTH             |   NUM_NAMES   |               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
//   /                         NODE_NAME ARRAY  (variable len)       /
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   /                           STATISTICS      (variable len)      /
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func (h *Handler) processNameQueryResponse(packet packet, ip net.IP) error {

	log.Debug("nbns received name query packet")
	packet.printHeader()
	// Assume no questions
	if packet.qdCount() > 0 {
		log.Printf("unexpected qdcount %v ", packet.qdCount())
	}

	// Assume a single Response name
	if packet.anCount() <= 0 {
		return fmt.Errorf("unexpected ancount %v ", packet.anCount())
	}

	// variable len reading
	buf := bytes.NewBuffer(packet.payload())
	name := decodeNBNSName(buf)
	log.Printf("name: |%s|\n", name)

	var tmp16 uint16
	var numNames uint8
	binary.Read(buf, binary.BigEndian, &tmp16)    // type
	binary.Read(buf, binary.BigEndian, &tmp16)    // internet
	binary.Read(buf, binary.BigEndian, &tmp16)    // TTL is 32 bits
	binary.Read(buf, binary.BigEndian, &tmp16)    // TTL
	binary.Read(buf, binary.BigEndian, &tmp16)    // RDLength
	binary.Read(buf, binary.BigEndian, &numNames) // numNames

	tmpName := make([]byte, 16)
	table := []string{}
	for i := 0; i < int(numNames); i++ {
		binary.Read(buf, binary.BigEndian, &tmpName)
		binary.Read(buf, binary.BigEndian, &tmp16) // nameFlags
		// log.Infof("names %q  nFlags %02x", tmpName, tmp16)
		if (tmp16 & 0x8000) == 0x00 { // don't add to the table if this is group name
			t := strings.TrimRight(string(tmpName), " \x00")
			t = strings.TrimRight(t, " \x03") // not sure why some have 03 at the end
			t = strings.TrimRight(t, " \x1d") // not sure why some have 1d at the end
			table = append(table, t)
		}
	}

	entry := Entry{IP: ip, Name: table[0]} // first entry
	log.Info("nodes ", entry.Name, entry.IP, table)
	if h.notification != nil {
		log.Debugf("nbns send notification name %s ip %s", entry.Name, entry.IP)
		h.notification <- entry
	}

	return nil
}

// ListenAndServe main listening loop
func (h *Handler) ListenAndServe() error {
	g := GoroutinePool.Begin("nbns ListenAndServe")
	defer g.End()

	readBuffer := make([]byte, 1024)

	// h.conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
	for !g.Stopping() {
		_, udpAddr, err := h.conn.ReadFromUDP(readBuffer)
		if g.Stopping() {
			return nil
		}

		if err != nil {
			if err, ok := err.(net.Error); ok && err.Timeout() {
				log.Debug("NBNS timeout reading result", err)
				continue
			}

			switch t := err.(type) {

			case *net.OpError:
				if t.Op == "dial" {
					log.Error("NBNS error unknown host", err)
				} else if t.Op == "read" {
					log.Debug("NBNS error conn refused", err)
				}

			case syscall.Errno:
				if t == syscall.ECONNREFUSED {
					log.Debug("NBNS error connection refused", err)
				}

			default:
				log.Error("NBNS error reading result default", err)
			}

			return err
		}

		log.Info("nbns received nbns packet from IP ", *udpAddr)
		packet := packet(readBuffer)
		switch {
		case packet.opcode() == opcodeQuery && packet.response() == 1:
			if err := h.processNameQueryResponse(packet, udpAddr.IP); err != nil {
				log.Error(err)
			}

		default:
			log.Infof("nbns packet opcode=%v not implemented ", packet.opcode())
			packet.printHeader()
		}

	}

	return nil
}
