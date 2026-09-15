package gopocs

import (
	"crypto/aes"
	"crypto/cipher"
	"dddd/internal/common/report"
	"dddd/internal/structs"
	"dddd/internal/utils"
	"encoding/base64"
	"net"
	"os"
	"strings"
	"sync"
)

var PluginList = map[string]interface{}{
	"NetBios-GetHostInfo":  NetBIOS,
	"RPC-GetHostInfo":      Findnet,
	"SSH-Crack":            SshScan,
	"FTP-Crack":            FtpScan,
	"Mysql-Crack":          MysqlScan,
	"Mssql-Crack":          MssqlScan,
	"Oracle-Crack":         OracleScan,
	"MongoDB-Crack":        MongodbScan,
	"RDP-Crack":            RdpScan,
	"Redis-Crack":          RedisScan,
	"SMB-MS17-010":         MS17010,
	"PostgreSQL-Crack":     PostgresScan,
	"SMB-Crack":            SmbScan,
	"Telnet-Crack":         TelnetScan,
	"Memcache-Crack":       MemcachedScan,
	"JDWP-Scan":            JDWPScan,
	"Shiro-Key-Crack":      ShiroKeyCheck,
	"ADB-Scan":             ADBScan,
	"Elasticsearch-Unauth": ElasticsearchScan,
	"Zookeeper-Unauth":     ZookeeperScan,
	"MQTT-Unauth":          MQTTScan,
	"RabbitMQ-Unauth":      RabbitMQScan,
}

var WriteResultLock sync.Mutex

func ReadBytes(conn net.Conn) (result []byte, err error) {
	size := 4096
	buf := make([]byte, size)
	for {
		count, err := conn.Read(buf)
		if err != nil {
			break
		}
		result = append(result, buf[0:count]...)
		if count < size {
			break
		}
	}
	if len(result) > 0 {
		err = nil
	}
	return result, err
}

var key = "0123456789abcdef"

func AesDecrypt(cryted string, key string) string {
	crytedByte, err := base64.StdEncoding.DecodeString(cryted)
	if err != nil {
		return ""
	}
	k := []byte(key)
	block, err := aes.NewCipher(k)
	if err != nil {
		return ""
	}
	// 获取秘钥块的长度
	blockSize := block.BlockSize()
	// 加密模式
	blockMode := cipher.NewCBCDecrypter(block, k[:blockSize])
	// 创建数组
	orig := make([]byte, len(crytedByte))
	// 解密
	blockMode.CryptBlocks(orig, crytedByte)
	// 去补全码
	orig = PKCS7UnPadding(orig)
	return string(orig)
}

// 去码
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func generateKeys(key string) []string {
	var results []string
	results = append(results, strings.ToLower(key))
	results = append(results, strings.ToUpper(key))
	results = append(results, strings.ToUpper(strings.ToUpper(key[:1])+key[1:]))
	return results
}

func splitUserPass(userPasswd string) (user string, oriPass string) {
	sp := strings.Split(userPasswd, " : ")
	user = ""
	oriPass = ""
	if len(sp) != 2 {
		user = sp[0]
		oriPass = ""
	} else {
		user = sp[0]
		oriPass = sp[1]
	}
	user = strings.TrimSuffix(user, "\r")
	oriPass = strings.TrimSuffix(oriPass, "\r")
	return user, oriPass
}

func sortUserPassword(info *structs.HostInfo, UserPasswdDict string, DefaultKeys []string) []structs.UserPasswd {
	var userPasswdList []structs.UserPasswd
	var upList []string

	if structs.GlobalConfig.Password != "" {
		upList = append(upList, structs.GlobalConfig.Password)
	} else {
		// 基础字典：目标自带凭证 + 内嵌字典
		upList = append(upList, info.UserPass...)
		// 兼容Windows
		UserPasswdDict = strings.ReplaceAll(UserPasswdDict, "\r\n", "\n")
		for _, v := range strings.Split(UserPasswdDict, "\n") {
			upList = append(upList, v)
		}

		if structs.GlobalConfig.PasswordFile != "" {
			b, err := os.ReadFile(structs.GlobalConfig.PasswordFile)
			if err == nil {
				t := strings.ReplaceAll(string(b), "\r\n", "\n")
				fileEntries := []string{}
				for _, v := range strings.Split(t, "\n") {
					if !strings.Contains(v, " : ") {
						continue
					}
					fileEntries = append(fileEntries, v)
				}
				if structs.GlobalConfig.PasswordFileAppend {
					// 追加模式：保留基础字典，把外部文件追加到末尾
					upList = append(upList, fileEntries...)
				} else {
					// 覆盖模式：仅用外部文件
					upList = fileEntries
				}
			}
		}
	}
	upList = utils.RemoveDuplicateElement(upList)

	// 统计变形后的字典
	for _, userPasswd := range upList {
		user, oriPass := splitUserPass(userPasswd)

		if strings.Contains(oriPass, "{{key}}") {
			for _, sKey := range info.InfoStr {
				newKeys := generateKeys(sKey)
				for _, nKey := range newKeys {
					newPass := strings.Replace(oriPass, "{{key}}", nKey, -1)
					userPasswdList = append(userPasswdList, structs.UserPasswd{UserName: user, Password: newPass})
				}

			}
			for _, dk := range DefaultKeys {
				newKeys := generateKeys(dk)
				for _, nKey := range newKeys {
					newPass := strings.Replace(oriPass, "{{key}}", nKey, -1)
					userPasswdList = append(userPasswdList, structs.UserPasswd{UserName: user, Password: newPass})
				}
			}

		} else {
			userPasswdList = append(userPasswdList, structs.UserPasswd{UserName: user, Password: oriPass})
		}
	}
	return RemoveDuplicateUserPass(userPasswdList)
}

func RemoveDuplicateUserPass(input []structs.UserPasswd) []structs.UserPasswd {
	temp := map[structs.UserPasswd]struct{}{}
	var result []structs.UserPasswd
	for _, item := range input {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func CheckErrs(err error) bool {
	if err == nil {
		return false
	}
	errs := []string{
		"closed by the remote host", "too many connections",
		"i/o timeout", "EOF", "A connection attempt failed",
		"established connection failed", "connection attempt failed",
		"Unable to read", "is not allowed to connect to this",
		"no pg_hba.conf entry",
		"No connection could be made",
		"invalid packet size",
		"bad connection",
	}
	for _, key := range errs {
		if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(key)) {
			return true
		}
	}
	return false
}

func GoPocWriteResult(result structs.GoPocsResultType) {
	WriteResultLock.Lock()
	report.AddResultByGoPocResult(result)
	WriteResultLock.Unlock()
}

// initDic 初始化用于爆破的字典
func initDic() {
	// 爆破字典已通过 go:embed 编译进程序，运行时不再依赖外部 config/dict。
}
