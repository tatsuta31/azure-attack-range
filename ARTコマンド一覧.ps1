
# ARTをPowerShellで直接実行する方法
# ※ PowerShell は「管理者として実行」で開く

# ===================== 事前準備 =====================
# [毎回] このセッションだけスクリプト実行を許可
Set-ExecutionPolicy Bypass -Scope Process -Force

# [初回だけ] powershell-yaml モジュールをインストール
Install-Module -Name powershell-yaml -Scope CurrentUser -Force

# [毎回] ARTモジュールをインポート
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force

# 読み込めたか確認（出てくればOK）
Get-Command Invoke-AtomicTest
# ====================================================

# 技術IDに含まれるテストの一覧
Invoke-AtomicTest Txxxx.xxx -ShowDetailsBrief

# テストの詳細（-TestNumbers は省略可。省略すると全テスト）
Invoke-AtomicTest Txxxx.xxx -TestNumbers 1,2 -ShowDetails

# 前提条件の確認
Invoke-AtomicTest Txxxx.xxx -TestNumbers 1,2 -CheckPrereqs
# 足りないものをダウンロード
Invoke-AtomicTest Txxxx.xxx -TestNumbers 1,2 -GetPrereqs

# 実行（-TestNumbers を省略すると全テストが流れるので注意）
Invoke-AtomicTest Txxxx.xxx -TestNumbers 1,2

# テスト後の後片付け
Invoke-AtomicTest Txxxx.xxx -TestNumbers 1,2 -Cleanup
