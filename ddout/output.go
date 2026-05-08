package ddout

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
)

var (
	OutputType     string
	OutputFileName string
	ansiRegexp     = regexp.MustCompile(`\x1b\[[0-9;]*m`)
)

type WebInfo struct {
	Status string `json:"status,omitempty"`
	Title  string `json:"title,omitempty"`
}

type GoPocsResultType struct {
	PocName     string `json:"poc_name,omitempty"`
	Security    string `json:"security,omitempty"`
	Description string `json:"description,omitempty"`
	Target      string `json:"target,omitempty"`
	InfoLeft    string `json:"info_left,omitempty"`
	InfoRight   string `json:"info_right,omitempty"`
	ShowMsg     string `json:"show_msg,omitempty"`
}

type OutputMessage struct {
	Type          string           `json:"type,omitempty"`
	IP            string           `json:"ip,omitempty"`
	IPs           []string         `json:"ips,omitempty"`
	Port          string           `json:"port,omitempty"`
	Protocol      string           `json:"protocol,omitempty"`
	Web           WebInfo          `json:"web,omitempty"`
	Finger        []string         `json:"finger,omitempty"`
	Domain        string           `json:"domain,omitempty"`
	GoPoc         GoPocsResultType `json:"go_poc,omitempty"`
	URI           string           `json:"uri,omitempty"`
	City          string           `json:"city,omitempty"`
	AdditionalMsg string           `json:"am,omitempty"`
	Show          string           `json:"-"`
	Nuclei        string           `json:"nuclei,omitempty"`
}

func (o *OutputMessage) ToString() (string, error) {
	r := ""
	var err error

	// IP存活验证
	if o.Type == "IPAlive" {
		r = fmt.Sprintf("%s %s", aurora.BrightGreen("[Alive]").String(), aurora.BrightCyan(o.IP).String())
	} else if o.Type == "PortScan" {
		r = fmt.Sprintf("%s %s", aurora.BrightMagenta("[PortScan]").String(), aurora.BrightCyan(o.IP+":"+o.Port).String())
	} else if o.Type == "Nmap" {
		r = fmt.Sprintf("%s %s://%s", aurora.BrightYellow("[Nmap]").String(), aurora.Cyan(o.Protocol).String(), aurora.BrightCyan(o.IP+":"+o.Port).String())
	} else if o.Type == "Web" {
		r = fmt.Sprintf("%s %s %s", aurora.BrightBlue("[Web]").String(), colorizeStatus(o.Web.Status), aurora.BrightCyan(o.URI).String())
		if o.Web.Title != "" {
			r += " [" + aurora.White(o.Web.Title).String() + "]"
		}
	} else if o.Type == "DNS-Brute" {
		r = aurora.BrightMagenta("[Brute]").String() + " " + aurora.BrightCyan(o.Domain).String()
	} else if o.Type == "DNS-SubFinder" {
		r = aurora.BrightMagenta("[SubFinder]").String() + " " + aurora.BrightCyan(o.Domain).String()
	} else if o.Type == "CDN-Domain" {
		r = aurora.BrightYellow("[CDN-Domain]").String() + " " + aurora.BrightCyan(o.Domain).String()
	} else if o.Type == "RealIP" {
		r = aurora.BrightYellow("[RealIP]").String() + " " + aurora.BrightCyan(o.Domain).String() + " => "
		for _, v := range o.IPs {
			r += aurora.BrightCyan(v).String() + ","
		}
		r = r[:len(r)-1]
	} else if o.Type == "GoPoc" {
		r = aurora.BrightRed("[GoPoc]").String() + " " + colorizeSeverityLine(o.GoPoc.ShowMsg)
	} else if o.Type == "Finger" {
		//msg := "[Finger] " + fullURL + " "
		//msg += fmt.Sprintf("[%d] [", pathEntity.StatusCode)
		//for _, r := range results {
		//	msg += aurora.Cyan(r).String() + ","
		//}
		//msg = msg[:len(msg)-1] + "]"
		//if pathEntity.Title != "" {
		//	msg += fmt.Sprintf(" [%s]", pathEntity.Title)
		//}
		//gologger.Silent().Msg(msg)

		r = aurora.BrightGreen("[Finger]").String() + " " + aurora.BrightCyan(o.URI).String() + " "
		if o.Web.Status != "" {
			r += colorizeStatus(o.Web.Status) + " "
		}
		r += "["
		for _, c := range o.Finger {
			r += aurora.Cyan(c).String() + ","
		}
		r = r[:len(r)-1] + "]"
		if o.Web.Title != "" {
			r += fmt.Sprintf(" [%s]", aurora.White(o.Web.Title).String())
		}
	} else if o.Type == "Active-Finger" {
		r = aurora.BrightGreen("[Active-Finger]").String() + " " + aurora.BrightCyan(o.URI).String() + " ["
		for _, c := range o.Finger {
			r += aurora.Cyan(c).String() + ","
		}
		r = r[:len(r)-1] + "]"
	} else if o.Type == "Domain-Bind" {
		r = fmt.Sprintf("%s %s %s", aurora.BrightYellow("[Domain-Bind]").String(), colorizeStatus(o.Web.Status), aurora.BrightCyan(o.URI).String())
	} else if o.Type == "Hunter" {
		r = aurora.BrightMagenta("[Hunter]").String() + " "
		if o.URI == "" {
			r += aurora.Cyan(o.Protocol).String() + "://" + aurora.BrightCyan(o.IP+":"+o.Port).String()
		} else {
			r += fmt.Sprintf("%s %s [%s] [%s]", colorizeStatus(o.Web.Status), aurora.BrightCyan(o.URI).String(), aurora.White(o.Web.Title).String(), aurora.BrightBlack(o.City).String())
		}
	} else if o.Type == "Fofa" {
		r = aurora.BrightMagenta("[Fofa]").String() + " " + o.Show
	} else if o.Type == "Quake" {
		r = aurora.BrightMagenta("[Quake]").String() + " " + o.Show
	} else if o.Type == "Nuclei" {
		r = aurora.BrightRed("[Nuclei]").String() + " " + colorizeSeverityLine(o.Show)
	} else if o.Type == "API-Unauth" {
		r = fmt.Sprintf("%s %s %s", aurora.BrightRed("[API-Unauth]").String(), colorizeStatus(o.Web.Status), aurora.BrightCyan(o.URI).String())
		if o.Web.Title != "" {
			r += " [" + aurora.White(o.Web.Title).String() + "]"
		}
	} else {
		err = fmt.Errorf("error OutputMessage Type: %s", o.Type)
	}

	if err == nil && o.AdditionalMsg != "" {
		r += " [" + aurora.BrightBlue(o.AdditionalMsg).String() + "]"
	}

	return r, err
}

func (o *OutputMessage) ToJson() (string, error) {
	b, err := json.Marshal(o)
	return string(b), err
}

func writeFile(result string) {
	filename := OutputFileName

	var text = []byte(result + "\n")
	fl, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Open %s error, %v\n", filename, err)
		return
	}
	_, err = fl.Write(text)
	fl.Close()
	if err != nil {
		fmt.Printf("Write %s error, %v\n", filename, err)
	}
}

func FormatOutput(o OutputMessage) {
	if OutputFileName == "" {
		return
	}
	s, err := o.ToString()
	if err != nil {
		return
	}
	gologger.Silent().Msg(s)

	if s == "" {
		return
	}

	if OutputType == "text" {
		writeFile(stripANSI(s))
	} else if OutputType == "json" {
		j, e := o.ToJson()
		if e == nil {
			writeFile(j)
		}
	}

}

func stripANSI(s string) string {
	return ansiRegexp.ReplaceAllString(s, "")
}

func colorizeStatus(status string) string {
	switch status {
	case "200", "201", "202", "204":
		return aurora.BrightGreen("[" + status + "]").String()
	case "301", "302", "303", "307", "308":
		return aurora.BrightYellow("[" + status + "]").String()
	case "":
		return "[]"
	default:
		return aurora.BrightRed("[" + status + "]").String()
	}
}

func colorizeSeverityLine(line string) string {
	replacer := strings.NewReplacer(
		"[critical]", aurora.BrightRed("[critical]").Bold().String(),
		"[high]", aurora.BrightRed("[high]").String(),
		"[medium]", aurora.BrightYellow("[medium]").String(),
		"[low]", aurora.BrightBlue("[low]").String(),
		"[info]", aurora.BrightGreen("[info]").String(),
		"[unknown]", aurora.BrightBlack("[unknown]").String(),
		"[CRITICAL]", aurora.BrightRed("[CRITICAL]").Bold().String(),
		"[HIGH]", aurora.BrightRed("[HIGH]").String(),
		"[MEDIUM]", aurora.BrightYellow("[MEDIUM]").String(),
		"[LOW]", aurora.BrightBlue("[LOW]").String(),
		"[INFO]", aurora.BrightGreen("[INFO]").String(),
		"[UNKNOWN]", aurora.BrightBlack("[UNKNOWN]").String(),
	)
	return replacer.Replace(line)
}
