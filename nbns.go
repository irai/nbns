package nbns

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"time"
)

// Handler create a new NBNS handler
type Handler struct {
	conn          *net.UDPConn
	broadcastAddr net.IP
	notification  chan<- Entry
}

// Debug tells the package to log Info and lower messages
// Default is to log only Error and Warning; set it to true to log other messages
var Debug bool

// Entry holds a NBNS name entry
type Entry struct {
	IP   net.IP
	Name string
}

// New create a NBNS handler
func New(ipNet net.IPNet) (handler *Handler, err error) {
	// srcAddr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")

	handler = &Handler{}
	if handler.conn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: nil, Port: 137}); err != nil {
		return nil, fmt.Errorf("nbns failed to bind UDP port 137: %w ", err)
	}

	// calculate broadcast addr
	handler.broadcastAddr = net.IP(make([]byte, 4))
	for i := range ipNet.IP {
		handler.broadcastAddr[i] = ipNet.IP[i] | ^ipNet.Mask[i]
	}
	return handler, nil
}

// Close releases the underlying udp conn
func (h *Handler) Close() error {
	return h.conn.Close()
}

// SendQuery send NBNS node status request query
func (h *Handler) SendQuery(ctx context.Context, ip net.IP) (err error) {

	packet := nodeStatusRequestWireFormat(`*               `)
	// packet.printHeader()

	if ip == nil || ip.Equal(net.IPv4zero) {
		return fmt.Errorf("invalid IP=%v", ip)
	}
	// ip[3] = 255 // Network broadcast

	// To broadcast, use network broadcast i.e 192.168.0.255 for example.
	targetAddr := &net.UDPAddr{IP: ip, Port: 137}
	if _, err = h.conn.WriteToUDP(packet, targetAddr); err != nil {
		if ctx.Err() == nil { // not cancelled
			return fmt.Errorf("nbns failed to send packet: %w", err)
		}
	}
	return nil
}

// AddNotificationChannel set the notification channel for new names
func (h *Handler) AddNotificationChannel(notification chan<- Entry) {
	h.notification = notification
}

func (h *Handler) broadcastLoop(ctx context.Context, interval time.Duration) error {
	if Debug {
		log.Printf("nbns broadcastLoop")
		defer log.Printf("nbns broadcastLoop terminated")
	}

	for {
		h.SendQuery(ctx, h.broadcastAddr)
		select {
		case <-ctx.Done():
			return nil

		case <-time.After(interval):
		}
	}

}

// ListenAndServe main listening loop
func (h *Handler) ListenAndServe(ctx context.Context, interval time.Duration) error {

	go h.broadcastLoop(ctx, interval)

	readBuffer := make([]byte, 1024)

	for {
		_, udpAddr, err := h.conn.ReadFromUDP(readBuffer)
		if ctx.Err() != nil {
			return nil
		}

		if err != nil {
			opErr := &net.OpError{}
			if errors.As(err, &opErr) {
				if opErr.Timeout() {
					if Debug {
						log.Printf("nbns timeout: %s", err)
					}
					continue
				}
			}
			return fmt.Errorf("nbns error fail to read udp: %w", err)
		}

		packet := packet(readBuffer)
		switch {
		case packet.opcode() == opcodeQuery && packet.response() == 1:
			if Debug {
				log.Printf("nbns received nbns response from=%+v", *udpAddr)
			}

			entry, err := parseNodeStatusResponsePacket(packet, udpAddr.IP)
			if err != nil {
				log.Printf("nbns error parsing response: %s", err)
				continue
			}

			if h.notification != nil {
				if Debug {
					if Debug {
						log.Printf("nbns send notification name %s ip %s", entry.Name, entry.IP)
					}
				}
				h.notification <- entry
			}

		case packet.response() == 0:
			if packet.trnID() != sequence { // ignore our own request
				if Debug {
					log.Printf("nbns not implemented - recvd nbns request from=%+v", *udpAddr)
					packet.printHeader()
				}
			}

		default:
			log.Printf("nbns not implemented opcode=%v ", packet.opcode())
			if Debug {
				packet.printHeader()
			}
		}
	}
}
