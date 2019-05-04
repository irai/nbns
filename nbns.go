package nbns

import (
	"fmt"
	"net"
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
	if handler.conn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 137}); err != nil {
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

	packet := toNameQueryWireFormat(`*`)
	packet.print()

	targetAddr := &net.UDPAddr{IP: net.IPv4bcast, Port: 137}
	if _, err = h.conn.WriteToUDP(packet, targetAddr); err != nil {
		log.Error("NPNS failed to send nbns discovery ", err)
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
		if packet.response() != 1 {
			log.Info("nbns received nbns request - not implemented - skipping")
			packet.print()
			continue
		}

		switch packet.opcode() {
		case opcodeQuery:
			packet.print()
			h.processNameQueryResponse(packet, udpAddr.IP)

		default:
			log.Infof("nbns packet opcode=%v not implemented ", packet.opcode())
			packet.print()
			continue
		}

	}

	return nil
}

func (h *Handler) processNameQueryResponse(packet packet, ip net.IP) error {

	// Assume a single Question name
	if packet.qdCount() > 0 {
		return fmt.Errorf("unexpected qdcount %v ", packet.qdCount())
	}

	// Assume a single Response name
	if packet.anCount() > 0 {
		return fmt.Errorf("unexpected ancount %v ", packet.anCount())
	}
	name := decodeNBNSName(packet.payload())

	/**
	nodename := []byte{}
	for i := range newPkt.NodeNames {
		if strings.Contains(newPkt.NodeNames[i], "WORKGROUP") ||
			strings.Contains(newPkt.NodeNames[i], "__") {
			continue
		}
		log.Infof("nodename = %s  len %v", newPkt.NodeNames[i], len(newPkt.NodeNames[i]))
		nodename = make([]byte, len(newPkt.NodeNames[i]))
		copy(nodename, newPkt.NodeNames[i])
		//nodename = nodename[0:len(newPkt.NodeNames[i])]
		break
	}
	**/

	log.Info("Got name", string(name))
	if h.notification != nil {
		h.notification <- Entry{IP: ip, Name: name}
	}

	return nil
}
