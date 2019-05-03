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
		fmt.Println("Command: (q)uit | (s)end ipv4 | (p)rint | (g) loG <level>")
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
			// ip := net.ParseIP(text[2:])
			// if ip == nil {
				// log.Error("invalid ip ", text[2:])
				// break
			// }
			h.SendQuery(net.IPv4zero)

		case 'p':
			// c.Print()

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
