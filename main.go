package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// 判断一个 IPv4 地址是否属于私有地址
func isPrivateIPv4(ip net.IP) bool {
	// 私有地址范围
	privateIPv4Ranges := []string{
		"10.",        // 10.0.0.0 - 10.255.255.255
		"172.16.",    // 172.16.0.0 - 172.31.255.255
		"192.168.",   // 192.168.0.0 - 192.168.255.255
	}
	for _, prefix := range privateIPv4Ranges {
		if strings.HasPrefix(ip.String(), prefix) {
			return true
		}
	}
	return false
}

// 随机生成一个公网 IPv4 地址
func randomIPv4() net.IP {
	var ip net.IP
	for {
		// 随机生成一个 IPv4 地址
		ip = net.IPv4(byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)))
		// 如果是私有地址，则重新生成
		if !isPrivateIPv4(ip) {
			return ip
		}
	}
}

// 随机生成一个公网 IPv6 地址
func randomIPv6() net.IP {
	var ip net.IP
	for {
		// 随机生成一个 IPv6 地址（不使用 fc00::/7 范围）
		ip = net.ParseIP(fmt.Sprintf("2001:db8::%x:%x", rand.Intn(65536), rand.Intn(65536)))
		// 如果是私有地址，则重新生成
		if !strings.HasPrefix(ip.String(), "fc") {
			return ip
		}
	}
}

// 处理 DNS 请求
func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	// 创建响应
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	// 记录请求的详细信息
	log.Printf("Received DNS query: %s %s", r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype])

	// 如果是 A 记录（IPv4），返回一个随机的 IPv4 地址
	if r.Question[0].Qtype == dns.TypeA {
		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: randomIPv4(),
		}
		m.Answer = append(m.Answer, rr)
		log.Printf("Returning IPv4 address: %s", rr.A)
	}

	// 如果是 AAAA 记录（IPv6），返回一个随机的 IPv6 地址
	if r.Question[0].Qtype == dns.TypeAAAA {
		rr := &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			AAAA: randomIPv6(),
		}
		m.Answer = append(m.Answer, rr)
		log.Printf("Returning IPv6 address: %s", rr.AAAA)
	}

	// 发送响应
	err := w.WriteMsg(m)
	if err != nil {
		log.Printf("Failed to send DNS response: %s", err)
	} else {
		log.Printf("Successfully sent DNS response.")
	}
}

func main() {
	// 定义命令行参数
	address := flag.String("address", "0.0.0.0", "DNS server listen address")
	port := flag.String("port", "53", "DNS server listen port")
	flag.Parse()

	// 构造监听地址
	listenAddr := fmt.Sprintf("%s:%s", *address, *port)

	// 随机种子
	rand.Seed(time.Now().UnixNano())

	// 创建 DNS 服务器
	server := &dns.Server{
		Addr: listenAddr, // 使用命令行参数指定的地址
		Net:  "udp",
	}

	// 注册处理函数
	dns.HandleFunc(".", handleRequest)

	// 启动 DNS 服务器
	log.Printf("DNS server is listening on %s", listenAddr)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start DNS server: %s", err)
	}
}