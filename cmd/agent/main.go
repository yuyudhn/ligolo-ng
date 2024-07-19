package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"github.com/hashicorp/yamux"
	"github.com/nicocha30/ligolo-ng/pkg/agent"
	"github.com/nicocha30/ligolo-ng/pkg/utils/selfcert"
	"github.com/sirupsen/logrus"
	goproxy "golang.org/x/net/proxy"
	"net"
	"os"
	"strings"
	"time"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type Config struct {
	IgnoreCertificate bool
	AcceptFingerprint string
	Verbose           bool
	Retry             bool
	SocksProxy        string
	SocksUser         string
	SocksPass         string
	ServerAddr        string
	BindAddr          string
}

func main() {
	config := Config{}
	showMenu(&config)
}

func showMenu(config *Config) {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("ligolo-agent~# ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		commands := strings.SplitN(input, " ", 2)

		switch commands[0] {
		case "connect":
			if len(commands) < 2 {
				fmt.Println("Usage: connect <server_address>")
			} else {
				config.ServerAddr = commands[1]
			}
		case "ignore-cert":
			if len(commands) < 2 {
				fmt.Println("Usage: ignore-cert <true/false>")
			} else {
				config.IgnoreCertificate = commands[1] == "true"
			}
		case "accept-fingerprint":
			if len(commands) < 2 {
				fmt.Println("Usage: accept-fingerprint <fingerprint>")
			} else {
				config.AcceptFingerprint = commands[1]
			}
		case "verbose":
			if len(commands) < 2 {
				fmt.Println("Usage: verbose <true/false>")
			} else {
				config.Verbose = commands[1] == "true"
			}
		case "retry":
			if len(commands) < 2 {
				fmt.Println("Usage: retry <true/false>")
			} else {
				config.Retry = commands[1] == "true"
			}
		case "socks":
			if len(commands) < 2 {
				fmt.Println("Usage: socks <proxy_address>")
			} else {
				config.SocksProxy = commands[1]
			}
		case "socks-user":
			if len(commands) < 2 {
				fmt.Println("Usage: socks-user <username>")
			} else {
				config.SocksUser = commands[1]
			}
		case "socks-pass":
			if len(commands) < 2 {
				fmt.Println("Usage: socks-pass <password>")
			} else {
				config.SocksPass = commands[1]
			}
		case "bind":
			if len(commands) < 2 {
				fmt.Println("Usage: bind <bind_address>")
			} else {
				config.BindAddr = commands[1]
			}
		case "start":
			startAgent(config)
		case "menu":
			printMenu()
		case "exit":
			return
		default:
			fmt.Println("Unknown command")
		}
	}
}

func printMenu() {
	fmt.Println("Available commands:")
	fmt.Println("  connect <server_address>       - Connect to proxy (domain:port)")
	fmt.Println("  ignore-cert <true/false>       - Ignore TLS certificate validation (dangerous)")
	fmt.Println("  accept-fingerprint <fingerprint> - Accept certificates matching the specified SHA256 fingerprint (hex format)")
	fmt.Println("  verbose <true/false>           - Enable verbose mode")
	fmt.Println("  retry <true/false>             - Auto-retry on error")
	fmt.Println("  socks <proxy_address>          - SOCKS5 proxy address (ip:port)")
	fmt.Println("  socks-user <username>          - SOCKS5 username")
	fmt.Println("  socks-pass <password>          - SOCKS5 password")
	fmt.Println("  bind <bind_address>            - Bind to IP:port")
	fmt.Println("  start                          - Start the agent")
	fmt.Println("  menu                           - Show this menu")
	fmt.Println("  exit                           - Exit the program")
}

func startAgent(config *Config) {
	var tlsConfig tls.Config

	logrus.SetReportCaller(config.Verbose)

	if config.Verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if config.BindAddr != "" {
		selfcrt := selfcert.NewSelfCert(nil)
		crt, err := selfcrt.GetCertificate(config.BindAddr)
		if err != nil {
			logrus.Fatal(err)
		}
		logrus.Warnf("TLS Certificate fingerprint is: %X\n", sha256.Sum256(crt.Certificate[0]))
		tlsConfig.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return crt, nil
		}
		lis, err := net.Listen("tcp", config.BindAddr)
		if err != nil {
			logrus.Fatal(err)
		}
		logrus.Infof("Listening on %s...", config.BindAddr)
		for {
			conn, err := lis.Accept()
			if err != nil {
				logrus.Error(err)
				continue
			}
			logrus.Infof("Got connection from: %s\n", conn.RemoteAddr())
			tlsConn := tls.Server(conn, &tlsConfig)

			if err := connect(tlsConn); err != nil {
				logrus.Error(err)
			}
		}
	}

	if config.ServerAddr == "" {
		logrus.Fatal("please, specify the target host user -connect host:port")
	}
	host, _, err := net.SplitHostPort(config.ServerAddr)
	if err != nil {
		logrus.Fatal("invalid connect address, please use host:port")
	}
	tlsConfig.ServerName = host
	if config.IgnoreCertificate {
		logrus.Warn("warning, certificate validation disabled")
		tlsConfig.InsecureSkipVerify = true
	}

	var conn net.Conn

	for {
		var err error
		if config.SocksProxy != "" {
			if _, _, err := net.SplitHostPort(config.SocksProxy); err != nil {
				logrus.Fatal("invalid socks5 address, please use host:port")
			}
			conn, err = sockDial(config.ServerAddr, config.SocksProxy, config.SocksUser, config.SocksPass)
		} else {
			conn, err = net.Dial("tcp", config.ServerAddr)
		}
		if err == nil {
			if config.AcceptFingerprint != "" {
				tlsConfig.InsecureSkipVerify = true
				tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					crtFingerprint := sha256.Sum256(rawCerts[0])
					crtMatch, err := hex.DecodeString(config.AcceptFingerprint)
					if err != nil {
						return fmt.Errorf("invalid cert fingerprint: %v\n", err)
					}
					if bytes.Compare(crtMatch, crtFingerprint[:]) != 0 {
						return fmt.Errorf("certificate does not match fingerprint: %X != %X", crtFingerprint, crtMatch)
					}
					return nil
				}
			}
			tlsConn := tls.Client(conn, &tlsConfig)

			err = connect(tlsConn)
		}
		logrus.Errorf("Connection error: %v", err)
		if config.Retry {
			logrus.Info("Retrying in 5 seconds.")
			time.Sleep(5 * time.Second)
		} else {
			logrus.Fatal(err)
		}
	}
}

func sockDial(serverAddr string, socksProxy string, socksUser string, socksPass string) (net.Conn, error) {
	proxyDialer, err := goproxy.SOCKS5("tcp", socksProxy, &goproxy.Auth{
		User:     socksUser,
		Password: socksPass,
	}, goproxy.Direct)
	if err != nil {
		logrus.Fatalf("socks5 error: %v", err)
	}
	return proxyDialer.Dial("tcp", serverAddr)
}

func connect(conn net.Conn) error {
	yamuxConn, err := yamux.Server(conn, yamux.DefaultConfig())
	if err != nil {
		return err
	}

	logrus.WithFields(logrus.Fields{"addr": conn.RemoteAddr()}).Info("Connection established")

	for {
		conn, err := yamuxConn.Accept()
		if err != nil {
			return err
		}
		go agent.HandleConn(conn)
	}
}
