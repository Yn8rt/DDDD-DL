package gopocs

import (
	"dddd/internal/ddout"
	"dddd/internal/structs"
)

func emitUnauthGoPoc(pocName, security, target, description, infoLeft, infoRight, showMsg string) {
	ddout.FormatOutput(ddout.OutputMessage{
		Type:     "GoPoc",
		IP:       "",
		IPs:      nil,
		Port:     "",
		Protocol: "",
		Web:      ddout.WebInfo{},
		Finger:   nil,
		Domain:   "",
		GoPoc: ddout.GoPocsResultType{
			PocName:     pocName,
			Security:    security,
			Target:      target,
			InfoLeft:    infoLeft,
			InfoRight:   infoRight,
			Description: description,
			ShowMsg:     showMsg,
		},
		AdditionalMsg: "",
	})

	GoPocWriteResult(structs.GoPocsResultType{
		PocName:     pocName,
		Security:    security,
		Target:      target,
		InfoLeft:    infoLeft,
		InfoRight:   infoRight,
		Description: description,
	})
}

func limitInfoRight(value string) string {
	const maxLen = 4096
	if len(value) <= maxLen {
		return value
	}
	return value[:maxLen] + "\n...内容已截断..."
}
