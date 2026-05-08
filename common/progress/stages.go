package progress

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/logrusorgru/aurora"
)

// Stage 扫描阶段，用于汇总每个阶段耗时
type Stage struct {
	Name     string
	Start    time.Time
	Duration time.Duration
	// done 显式标记阶段已结束
	// Windows 上 time.Now() 精度约 15.6ms, 极快阶段可能得到 Duration=0,
	// 若仅靠 Duration==0 判断会误触发 fallback 得到错误的总耗时
	done bool
}

var (
	stagesMu sync.Mutex
	stages   []*Stage
)

// StartStage 登记并返回新阶段
func StartStage(name string) *Stage {
	s := &Stage{Name: name, Start: time.Now()}
	stagesMu.Lock()
	stages = append(stages, s)
	stagesMu.Unlock()
	return s
}

// Done 结束阶段并记录耗时
func (s *Stage) Done() {
	if s == nil {
		return
	}
	stagesMu.Lock()
	defer stagesMu.Unlock()
	if s.done {
		return
	}
	s.Duration = time.Since(s.Start)
	s.done = true
}

// PrintSummary 在程序结束时打印所有阶段耗时
// 输出到 stderr, 非 tty 下也会打印简单文本
func PrintSummary() {
	stagesMu.Lock()
	defer stagesMu.Unlock()
	if len(stages) == 0 {
		return
	}

	var total time.Duration
	maxNameWidth := 0
	for _, s := range stages {
		w := displayWidth(s.Name)
		if w > maxNameWidth {
			maxNameWidth = w
		}
		// 对未显式 Done 的 stage fallback 计算; 否则用真实 Duration (即使为 0)
		if !s.done {
			s.Duration = time.Since(s.Start)
			s.done = true
		}
		total += s.Duration
	}

	fmt.Fprintln(os.Stderr, "\n"+aurora.BrightBlue("========== 扫描阶段耗时汇总 ==========").String())
	for _, s := range stages {
		name := aurora.BrightCyan(s.Name).String()
		duration := aurora.BrightYellow(shortDuration(s.Duration)).String()
		fmt.Fprintf(os.Stderr, "  %s%s  %s\n",
			name, strings.Repeat(" ", maxNameWidth-displayWidth(s.Name)),
			duration)
	}
	totalLabel := "总耗时"
	fmt.Fprintf(os.Stderr, "  %s%s  %s\n",
		aurora.BrightGreen(totalLabel).String(), strings.Repeat(" ", maxNameWidth-displayWidth(totalLabel)),
		aurora.BrightGreen(shortDuration(total)).String())
	fmt.Fprintln(os.Stderr, aurora.BrightBlue("======================================").String())
}

// displayWidth 返回字符串占用的终端列宽 (ASCII=1, 中文=2)
// 解决 fmt %-*s 按字节对齐导致中文列错位
func displayWidth(s string) int {
	w := 0
	for _, r := range s {
		if r < 128 {
			w++
		} else {
			w += 2
		}
	}
	return w
}

// ResetStages 清空，方便测试
func ResetStages() {
	stagesMu.Lock()
	stages = nil
	stagesMu.Unlock()
}

func FormatDuration(d time.Duration) string {
	return shortDuration(d)
}
