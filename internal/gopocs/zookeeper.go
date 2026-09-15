package gopocs

import (
	"dddd/internal/common"
	"dddd/internal/structs"
	"fmt"
	"net"
	"strings"
	"time"
)

func ZookeeperScan(info *structs.HostInfo) error {
	_, err := ZookeeperUnauth(info)
	return err
}

func ZookeeperUnauth(info *structs.HostInfo) (bool, error) {
	addr := net.JoinHostPort(info.Host, info.Ports)
	response, err := zookeeperFourLetter(addr, "stat")
	if err != nil || response == "" {
		response, err = zookeeperFourLetter(addr, "ruok")
	}
	if err != nil {
		return false, err
	}

	lowerResp := strings.ToLower(response)
	if strings.Contains(lowerResp, "zookeeper version") || strings.Contains(lowerResp, "mode:") || strings.TrimSpace(lowerResp) == "imok" {
		showMsg := fmt.Sprintf("Zookeeper:%s Unauthorized", addr)
		infoLeft := fmt.Sprintf("Host: %s\nCommand: stat/ruok\n", addr)
		emitUnauthGoPoc("Zookeeper-Unauth", "MEDIUM", addr, "Zookeeper四字命令未授权访问", infoLeft, limitInfoRight(response), showMsg)
		return true, nil
	}
	return false, nil
}

func zookeeperFourLetter(addr, command string) (string, error) {
	conn, err := common.WrapperTcpWithTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return "", err
	}
	if _, err := conn.Write([]byte(command)); err != nil {
		return "", err
	}
	data, err := ReadBytes(conn)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
