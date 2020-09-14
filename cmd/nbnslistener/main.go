package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/irai/nbns"
)

var (
	netFlag = flag.String("cidr", "192.168.1.1/24", "network to broadcast nbns to")
)

func main() {
	flag.Parse()

	nbns.Debug = true

	_, network, err := net.ParseCIDR(*netFlag)
	if err != nil {
		log.Fatal("invalid CIDR ", err)
	}

	handler, err := nbns.New(*network)
	if err != nil {
		log.Fatal("error in nbns", err)
	}
	defer handler.Close()

	notify := make(chan nbns.Entry)
	go func() {
		for {
			select {
			// wait for n goroutines to finish
			case entry := <-notify:
				log.Println("got new name", entry)
			}
		}
	}()

	handler.AddNotificationChannel(notify)

	ctx, cancel := context.WithCancel(context.Background())

	go handler.ListenAndServe(ctx, time.Minute*1)

	cmd(ctx, handler)

	cancel()
	handler.Close()
}

func cmd(ctx context.Context, h *nbns.Handler) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("Command: (q)uit | (s)end <192.168.1.255> | (p)rint | (g) debug|error")
		fmt.Print("Enter command: ")
		text, _ := reader.ReadString('\n')
		text = strings.ToLower(strings.TrimRight(text, "\r\n")) // remove \r\n in windows or \n in linux
		fmt.Println(text)

		if text == "" || len(text) < 1 {
			continue
		}

		switch text[0] {
		case 'q':
			return
		case 'g':
			if len(text) < 3 {
				text = text + "   "
			}
			switch text[2:] {
			case "debug":
				nbns.Debug = true
			default:
				nbns.Debug = false
			}
			log.Printf("debug=%v\n", nbns.Debug)

		case 's':
			var ip net.IP
			if len(text) < 7 {
				log.Println("invalid IP. use a v4 address")
				break
			}
			ip = net.ParseIP(text[2:]) // ip = nil if invalid
			if err := h.SendQuery(ctx, ip); err != nil {
				log.Println("error sending packet to ip ", err)
			}

		case 'p':
			// h.PrintTable()

		}
	}
}
