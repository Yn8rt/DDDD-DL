@echo off
set LDFLAGS=-s -w

echo ========================================
echo    DDDD 跨平台编译脚本 (仅64位)
echo ========================================
echo.

echo [1/3] 编译 Windows x64...
set GOOS=windows&&set GOARCH=amd64&&go build -ldflags="%LDFLAGS%" -trimpath -o ./outp/dddd64.exe main.go
echo.

echo [2/3] 编译 Linux amd64...
set GOOS=linux&&set GOARCH=amd64&&go build -ldflags="%LDFLAGS%" -trimpath -o ./outp/dddd_linux64 main.go
echo.

echo [3/3] 编译 macOS arm64 (Apple Silicon)...
set GOOS=darwin&&set GOARCH=arm64&&go build -ldflags="%LDFLAGS%" -trimpath -o ./outp/dddd_darwin_arm64 main.go
echo.

echo ========================================
echo    编译完成！
echo ========================================
echo.
echo 生成的文件:
echo   - dddd64.exe (Windows x64)
echo   - dddd_linux64 (Linux amd64)
echo   - dddd_darwin_arm64 (macOS Apple Silicon)
echo.
pause