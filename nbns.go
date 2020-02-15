package nbns

import (
	"fmt"
	"net"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

// Handler create a new NBNS handler
type Handler struct {
	conn          *net.UDPConn
	broadcastAddr net.IP
	notification  chan<- Entry
}

// LogAll tells the package to log Info and lower messages
// Default is to log only Error and Warning; set it to true to log other messages
var LogAll bool

// Entry holds a NBNS name entry
type Entry struct {
	IP   net.IP
	Name string
}

// NewHandler create a NBNS handler
func NewHandler(network net.IPNet) (handler *Handler, err error) {
	// srcAddr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")

	handler = &Handler{}
	if handler.conn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: nil, Port: 137}); err != nil {
		log.Error("NBNS failed to bind UDP port 137 ", err)
		return nil, err
	}

	// calculate broadcast addr
	handler.broadcastAddr = net.IP(make([]byte, 4))
	for i := range network.IP {
		handler.broadcastAddr[i] = network.IP[i] | ^network.Mask[i]
	}
	return handler, nil

}

// SendQuery send NBNS node status request query
func (h *Handler) SendQuery(ip net.IP) (err error) {

	packet := nodeStatusRequestWireFormat(`*               `)
	// packet.printHeader()

	if ip == nil || ip.Equal(net.IPv4zero) {
		return fmt.Errorf("invalid IP nil %v", ip)
	}
	// ip[3] = 255 // Network broadcast

	// To broadcast, use network broadcast i.e 192.168.0.255 for example.
	targetAddr := &net.UDPAddr{IP: ip, Port: 137}
	if _, err = h.conn.WriteToUDP(packet, targetAddr); err != nil {
		if !GoroutinePool.Stopping() {
			log.Error("NPNS failed to send nbns packet ", err)
		}
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

func (h *Handler) broadcastLoop(interval time.Duration) {
	g := GoroutinePool.Begin("nbns broadcastLoop")
	defer g.End()

	for {
		h.SendQuery(h.broadcastAddr)
		select {
		case <-GoroutinePool.StopChannel:
			return

		case <-time.After(interval):
		}
	}

}

// ListenAndServe main listening loop
func (h *Handler) ListenAndServe(interval time.Duration) error {
	g := GoroutinePool.Begin("nbns ListenAndServe")
	defer g.End()

	go h.broadcastLoop(interval)

	readBuffer := make([]byte, 1024)

	for !g.Stopping() {
		_, udpAddr, err := h.conn.ReadFromUDP(readBuffer)
		if g.Stopping() {
			return nil
		}

		if err != nil {
			if err, ok := err.(net.Error); ok && err.Timeout() {
				if LogAll {
					log.Debug("NBNS timeout reading result", err)
				}
				continue
			}

			switch t := err.(type) {

			case *net.OpError:
				if t.Op == "dial" {
					log.Error("NBNS error unknown host", err)
				} else if t.Op == "read" {
					if LogAll {
						log.Debug("NBNS error conn refused", err)
					}
				}

			case syscall.Errno:
				if t == syscall.ECONNREFUSED {
					if LogAll {
						log.Debug("NBNS error connection refused", err)
					}
				}

			default:
				log.Error("NBNS error reading result default", err)
			}

			return err
		}

		packet := packet(readBuffer)
		switch {
		case packet.opcode() == opcodeQuery && packet.response() == 1:
			if LogAll {
				log.Info("nbns received nbns nodeStatusResponse from IP ", *udpAddr)
			}
			entry, err := parseNodeStatusResponsePacket(packet, udpAddr.IP)
			if err != nil {
				log.Error("error processing nodeStatusResponse ", err)
				return err
			}

			if h.notification != nil {
				if LogAll {
					if LogAll {
						log.Debugf("nbns send notification name %s ip %s", entry.Name, entry.IP)
					}
				}
				h.notification <- entry
			}

		case packet.response() == 0:
			if packet.trnID() != sequence { // ignore our own request
				if LogAll {
					log.Info("nbns not implemented - recvd nbns request from IP ", *udpAddr)
				}
				packet.printHeader()
			}

		default:
			if LogAll {
				log.Infof("nbns not implemented opcode=%v ", packet.opcode())
			}
			packet.printHeader()
		}

	}

	return nil
}
