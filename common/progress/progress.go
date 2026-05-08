package progress

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/logrusorgru/aurora"
)

// Bar 轻量级进度条
// 设计目标：
//  1. 高频 Add 不会高频刷屏（内部节流，最小 200ms 一次）
//  2. 完成后自动换行，不干扰 gologger 的后续输出
//  3. 支持未知总数场景（total=0）
//  4. 使用 \r 回车原地刷新，不污染 result.txt / audit.log
type Bar struct {
	name       string
	total      int64
	current    atomic.Int64
	startAt    time.Time
	lastRender time.Time
	mu         sync.Mutex
	done       chan struct{}
	finished   atomic.Bool
	// 节流间隔
	interval time.Duration
	// 是否启用（非 tty 场景关闭动画）
	enabled bool
}

// New 新建一个进度条。name 会显示在前面; total 为目标总数(0 表示未知)
func New(name string, total int) *Bar {
	b := &Bar{
		name:     name,
		total:    int64(total),
		startAt:  time.Now(),
		done:     make(chan struct{}),
		interval: 200 * time.Millisecond,
		enabled:  isTerminal(),
	}
	if b.enabled {
		go b.renderLoop()
	} else {
		// 非 tty 环境直接打印起始提示
		if total > 0 {
			fmt.Fprintf(os.Stderr, "[%s] 开始 (total=%d)...\n", aurora.BrightCyan(name).String(), total)
		} else {
			fmt.Fprintf(os.Stderr, "[%s] 开始...\n", aurora.BrightCyan(name).String())
		}
	}
	return b
}

// Add 增加进度值
func (b *Bar) Add(n int) {
	if b == nil {
		return
	}
	b.current.Add(int64(n))
}

// Set 设置当前进度值, 但只允许单调上升
// 调用者常用进度推送(如 httpx 多轮重试), n 可能回退到较小值;
// 若无条件覆盖会让 bar 倒退, 体验不好
func (b *Bar) Set(n int) {
	if b == nil {
		return
	}
	for {
		cur := b.current.Load()
		if int64(n) <= cur {
			return
		}
		if b.current.CompareAndSwap(cur, int64(n)) {
			return
		}
	}
}

// AddTotal 运行期动态追加总数(如扫描过程中新增目标)
func (b *Bar) AddTotal(n int) {
	if b == nil {
		return
	}
	atomic.AddInt64(&b.total, int64(n))
}

// Finish 标记完成并输出最终一行
func (b *Bar) Finish() {
	if b == nil {
		return
	}
	if !b.finished.CompareAndSwap(false, true) {
		return
	}
	close(b.done)
	if b.enabled {
		b.render(true)
		fmt.Fprint(os.Stderr, "\n")
		return
	}
	cur := b.current.Load()
	tot := atomic.LoadInt64(&b.total)
	elapsed := shortDuration(time.Since(b.startAt))
	// total=0 表示未知总数模式, 只打印已处理数避免 "X/0" 误导
	if tot <= 0 {
		fmt.Fprintf(os.Stderr, "[%s] 完成 (已处理 %d) 耗时 %s\n",
			aurora.BrightGreen(b.name).String(), cur, aurora.BrightYellow(elapsed).String())
		return
	}
	fmt.Fprintf(os.Stderr, "[%s] 完成 (%d/%d) 耗时 %s\n",
		aurora.BrightGreen(b.name).String(), cur, tot, aurora.BrightYellow(elapsed).String())
}

func (b *Bar) renderLoop() {
	ticker := time.NewTicker(b.interval)
	defer ticker.Stop()
	for {
		select {
		case <-b.done:
			return
		case <-ticker.C:
			b.render(false)
		}
	}
}

func (b *Bar) render(finalFlush bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	cur := b.current.Load()
	tot := atomic.LoadInt64(&b.total)
	elapsed := time.Since(b.startAt)

	var pct float64
	if tot > 0 {
		pct = float64(cur) / float64(tot) * 100
		if pct > 100 {
			pct = 100
		}
	}

	const barWidth = 24
	filled := 0
	if tot > 0 {
		filled = int(float64(barWidth) * float64(cur) / float64(tot))
		if filled > barWidth {
			filled = barWidth
		}
	}

	bar := make([]byte, barWidth)
	for i := 0; i < barWidth; i++ {
		if i < filled {
			bar[i] = '='
		} else if i == filled && !finalFlush {
			bar[i] = '>'
		} else {
			bar[i] = ' '
		}
	}

	var speed string
	if elapsed.Seconds() > 0.1 && cur > 0 {
		rate := float64(cur) / elapsed.Seconds()
		speed = fmt.Sprintf(" %.1f/s", rate)
	}

	var line string
	name := aurora.BrightCyan(b.name).String()
	barString := string(bar)
	if finalFlush {
		barString = aurora.BrightGreen(barString).String()
	} else {
		barString = aurora.BrightBlue(barString).String()
	}
	percentText := aurora.BrightYellow(fmt.Sprintf("(%.1f%%)", pct)).String()
	speedText := speed
	if speedText != "" {
		speedText = aurora.BrightMagenta(speedText).String()
	}
	elapsedText := aurora.BrightBlack(shortDuration(elapsed)).String()
	if tot > 0 {
		line = fmt.Sprintf("\r[%s] [%s] %d/%d %s%s %s ",
			name, barString, cur, tot, percentText, speedText, elapsedText)
	} else {
		line = fmt.Sprintf("\r[%s] %d%s %s ",
			name, cur, speedText, elapsedText)
	}

	fmt.Fprint(os.Stderr, line)
}

func shortDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) - m*60
		return fmt.Sprintf("%dm%ds", m, s)
	}
	h := int(d.Hours())
	m := int(d.Minutes()) - h*60
	return fmt.Sprintf("%dh%dm", h, m)
}
