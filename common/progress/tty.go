package progress

import (
	"os"

	"golang.org/x/term"
)

// isTerminal 判断 stderr 是否为 tty
// 非 tty（重定向到文件 / 管道）时不做进度动画，只打印简单摘要
func isTerminal() bool {
	return term.IsTerminal(int(os.Stderr.Fd()))
}
