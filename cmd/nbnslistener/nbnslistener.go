package main

import (
	"net"
	"bufio"
	"flag"
	"fmt"
	"github.com/irai/nbns"
	log "github.com/sirupsen/logrus"
	"os"
	"strings"
)

func main() {
	flag.Parse()

	setLogLevel("info")

	nbns, err := nbns.NewHandler()
	if err != nil {
		log.Fatal("error in nbns", err)
	}

	go nbns.ListenAndServe()

	cmd(nbns)

	nbns.Stop()

}

func cmd(h *nbns.Handler) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("Command: (q)uit | (s)end <192.168.1.255> | (p)rint | (g) loG <level>")
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
			err := setLogLevel(text[2:])
			if err != nil {
				log.Error("invalid level. valid levels (error, warn, info, debug) ", err)
				break
			}
		case 'l':
			l := log.GetLevel()
			setLogLevel("info") // quick hack to print table
			log.SetLevel(l)

		case 's':
			var ip net.IP
			if len(text) < 7 {
				log.Error("invalid IP. use a v4 address")
				break
			}
			ip = net.ParseIP(text[2:]) // ip = nil if invalid
			if err := h.SendQuery(ip); err != nil {
				log.Error("error sending packet to ip ", err)
			}

		case 'p':
			// h.Print()

		}
	}
}

func setLogLevel(level string) (err error) {

	if level != "" {
		l, err := log.ParseLevel(level)
		if err != nil {
			return err
		}
		log.SetLevel(l)
	}

	return nil
}
