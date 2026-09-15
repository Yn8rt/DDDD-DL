package gopocs

import (
	"crypto/tls"
	"dddd/internal/common"
	"dddd/internal/structs"
	"fmt"
	"net"
	"time"
)

func MQTTScan(info *structs.HostInfo) error {
	_, err := MQTTUnauth(info)
	return err
}

func MQTTUnauth(info *structs.HostInfo) (bool, error) {
	addr := net.JoinHostPort(info.Host, info.Ports)
	conn, err := mqttDial(addr, info.Ports)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(6 * time.Second)); err != nil {
		return false, err
	}

	packet := []byte{0x10, 0x10, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x1e, 0x00, 0x04, 'd', 'd', 'd', 'd'}
	if _, err := conn.Write(packet); err != nil {
		return false, err
	}

	buf := make([]byte, 4)
	n, err := conn.Read(buf)
	if err != nil {
		return false, err
	}
	if n >= 4 && buf[0] == 0x20 && buf[1] == 0x02 && buf[3] == 0x00 {
		_, _ = conn.Write([]byte{0xe0, 0x00})
		showMsg := fmt.Sprintf("MQTT:%s Anonymous", addr)
		infoLeft := fmt.Sprintf("Host: %s\nClientID: dddd\n", addr)
		infoRight := fmt.Sprintf("CONNACK: % x", buf[:n])
		emitUnauthGoPoc("MQTT-Unauth", "HIGH", addr, "MQTT匿名连接", infoLeft, infoRight, showMsg)
		return true, nil
	}
	return false, nil
}

func mqttDial(addr, port string) (net.Conn, error) {
	if port == "8883" {
		dialer := &net.Dialer{Timeout: 6 * time.Second}
		return tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	}
	return common.WrapperTcpWithTimeout("tcp", addr, 6*time.Second)
}
