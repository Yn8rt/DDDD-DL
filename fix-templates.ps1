# 修复 nuclei 模板中的旧协议语法
# requests: -> http:

$yamlFiles = Get-ChildItem -Path "common\config\pocs" -Recurse -Filter "*.yaml"
$fixedCount = 0

foreach ($file in $yamlFiles) {
    $content = Get-Content $file.FullName -Raw -Encoding UTF8

    if ($content -match '(?m)^requests:') {
        $newContent = $content -replace '(?m)^requests:', 'http:'
        $newContent | Set-Content $file.FullName -NoNewline -Encoding UTF8
        Write-Host "Fixed: $($file.Name)"
        $fixedCount++
    }
}

Write-Host ""
Write-Host "Total fixed: $fixedCount templates" -ForegroundColor Green
