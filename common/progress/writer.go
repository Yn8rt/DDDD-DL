package progress

import (
	"os"
	"sync"

	"github.com/projectdiscovery/gologger/levels"
)

// 避免与 progress bar 互相覆盖的 gologger writer
//
// 工作原理:
//  1. 每次 gologger 写入前，先输出 "\r\033[K" 把当前行清空
//     （progress bar 的 \r 会把光标停在 bar 行头部，不清空直接写日志会导致残影）
//  2. 然后写正常日志（gologger 自己会 append "\n"），光标落到下一行开头
//  3. bar 的下一次 render tick (<=200ms) 会在新空行重绘自己
//  4. 可见效果：日志不会丢、bar 始终浮现在最新行的下方
//
// 与 CLI writer 区别: 无论 level，一律写 stderr
//   - 原 CLI writer 对 LevelSilent 走 stdout: 结果行 (例 "[Web] http://x [200]")
//     但这些结果一般也希望和日志一起看，统一 stderr 更简单，
//     且 dddd 有 result.txt / json output 文件单独落盘，屏幕输出不影响数据完整性

type barAwareWriter struct {
	mu sync.Mutex
}

// NewBarAwareGoLoggerWriter 返回一个感知进度条的 gologger.Writer
// 使用方法: gologger.DefaultLogger.SetWriter(progress.NewBarAwareGoLoggerWriter())
func NewBarAwareGoLoggerWriter() *barAwareWriter {
	return &barAwareWriter{}
}

// Write 实现 gologger/writer.Writer 接口
// 所有 level 统一走 stderr:
//  1. 原 CLI writer 把 Silent 级走 stdout, 其他走 stderr —
//     两个流混合输出 bar (stderr) 会看到结果行 (stdout) 乱序
//  2. dddd 有 -o result.txt/json 独立落盘, 所以屏幕输出统一 stderr 不影响数据完整性
//  3. 若需管道消费结果行, 改为 `2>&1` 或 `-o /dev/stdout` 即可
func (w *barAwareWriter) Write(data []byte, level levels.Level) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// tty 环境下先清空 bar 行, 避免 \r 残影
	if isTerminal() {
		_, _ = os.Stderr.Write([]byte("\r\033[K"))
	}

	_, _ = os.Stderr.Write(data)
	_, _ = os.Stderr.Write([]byte("\n"))
}
