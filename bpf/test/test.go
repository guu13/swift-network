package main

import (
	"fmt"
	"net"
	"os"
)

func sendUDPRequest(serverIP string, serverPort string) error {
	// 构建服务器地址
	serverAddr := fmt.Sprintf("%s:%s", serverIP, serverPort)

	// 建立连接
	conn, err := net.Dial("udp", serverAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// 发送数据
	message := []byte("Hello, UDP Server!")
	_, err = conn.Write(message)
	if err != nil {
		return err
	}
	fmt.Println("UDP request sent 1111 successfully!")

	// 发送数据
	_, err = conn.Write(message)
	if err != nil {
		return err
	}
	fmt.Println("UDP request sent 222 successfully!")

	return nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run udp_client.go <server_ip> <server_port> <message>")
		return
	}

	serverIP := os.Args[1]
	serverPort := os.Args[2]

	err := sendUDPRequest(serverIP, serverPort)
	if err != nil {
		fmt.Println("Error sending UDP request:", err)
	} else {
		fmt.Println("UDP request sent successfully!")
	}
}
