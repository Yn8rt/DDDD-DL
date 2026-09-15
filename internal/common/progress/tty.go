package progress

import (
	"os"
	"strings"

	"golang.org/x/term"
)

// isTerminal 判断 stderr 是否为 tty
// 非 tty（重定向到文件 / 管道）时不做进度动画，只打印简单摘要
func isTerminal() bool {
	return term.IsTerminal(int(os.Stderr.Fd()))
}

func supportsAnimation() bool {
	return progressModeAllowsAnimation(os.Getenv("TERM"), os.Getenv("DDDD_PROGRESS"), os.Getenv("CI") != "" || os.Getenv("CODEX_CI") != "") && isTerminal()
}

func progressModeAllowsAnimation(termName, mode string, ci bool) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "bar", "tty", "force":
		return true
	}
	return false
}
