"""Hand-written notes for the 98 selected ESCU rules (docs/escu-selection.md).

Each entry: rule name -> (summary_ja, art_tests, spl_fix, memo)
- summary_ja : what the rule looks for, in Japanese (one line)
- art_tests  : Atomic Red Team tests that should produce the logs ("Txxxx #n").
               Numbers follow the ART master index as of 2026-11-04. ATT&CK v18
               moved most Impair Defenses tests from T1562.001 / T1070.001 to T1685.x.
               Empty when the rule is reproduced by hand or not reproduced in the lab.
- spl_fix    : macro / SPL / lab setting needed before the rule can fire. "" = none known.
- memo       : anything else worth knowing (false positives, prerequisites).

Common prerequisites that apply to many rules are listed in COMMON_FIXES and referenced
by key from spl_fix (e.g. "CIM").
"""

COMMON_FIXES = {
    "CIM": (
        "CIM のデータモデル（Endpoint / Network_Traffic / Authentication）の対象 index を設定する。"
        "CIM アプリの設定で cim_Endpoint_indexes などのマクロに index=win OR index=unix を入れる。"
        "未設定だと、ロールの既定の検索 index しか見ないので win / unix のイベントが拾われないことがある"
    ),
    "AUDITD": (
        "マクロ linux_auditd を sourcetype=\"auditd\" から sourcetype=\"linux:audit\" に変更する"
        "（ラボの auditd は linux:audit で送っている）。proctitle が 16 進のまま取り込まれる場合は"
        "フィールド抽出も要確認"
    ),
    "PALO": "Palo Alto のログ（CIM 対応の TA）が前提。ラボでは発火しない",
}

NOTES = {
    # ---------------- 認証情報の窃取 ----------------
    "Windows Possible Credential Dumping": (
        "lsass.exe へのメモリ読み取りアクセス（特定の GrantedAccess と dbghelp/dbgcore を含む CallTrace）を検知する（Sysmon 10）",
        "T1003.001 #1, #4, #13", "",
        "2026-11-01 の ART で、対象の Sysmon 10 のログが出ることは確認済み（ルールの発火は未確認）"),
    "Access LSASS Memory for Dump Creation": (
        "dbghelp.dll / dbgcore.dll 経由で lsass.exe にアクセスした、ダンプ作成の痕跡を検知する（Sysmon 10）",
        "T1003.001 #1, #2", "", ""),
    "Dump LSASS via comsvcs DLL": (
        "rundll32 から comsvcs.dll の MiniDump を呼んで lsass をダンプしたコマンドラインを検知する",
        "T1003.001 #2", "CIM", "LOLBin の定番"),
    "Dump LSASS via procdump": (
        "procdump に -ma / -mm などを付けて lsass をダンプしたコマンドラインを検知する",
        "T1003.001 #1, #9", "CIM", ""),
    "Windows Non-System Account Targeting Lsass": (
        "SYSTEM 以外のアカウントが lsass.exe にアクセスしたことを検知する（Sysmon 10）",
        "T1003.001 #1, #2", "",
        "Caldera エージェントは SYSTEM で動くので、Caldera 経由では発火しない"),
    "Windows Sensitive Registry Hive Dump Via CommandLine": (
        "reg.exe で SAM / SYSTEM / SECURITY ハイブを保存・エクスポートしたことを検知する",
        "T1003.002 #1", "CIM", ""),
    "Creation of Shadow Copy": (
        "vssadmin / wmic でボリュームシャドウコピーを作成したことを検知する",
        "T1003.003 #1, #4", "CIM", "DC で実行すると NTDS.dit 窃取の下準備になる"),
    "Ntdsutil Export NTDS": (
        "ntdsutil で AD データベース（NTDS.dit）をエクスポートしたことを検知する",
        "T1003.003 #3", "CIM", "DC で実行"),
    "Windows AD Replication Request Initiated by User Account": (
        "ユーザーアカウントからのディレクトリ複製要求（DCSync）を検知する（4662）",
        "T1003.006 #1, #2", "",
        "DC で 4662 が出るには、ドメインのルートに監査（SACL）が必要。出なければ SACL を確認する"),
    "Windows AD Replication Request Initiated from Unsanctioned Location": (
        "DC 以外のコンピューターアカウントからの複製要求（DCSync）を検知する（4662）",
        "T1003.006 #1, #2", "", "上と同じく 4662 の SACL が前提"),
    "Kerberoasting spn request with RC4 encryption": (
        "RC4 暗号を指定したサービスチケット要求（Kerberoasting）を検知する（4769）",
        "T1558.003 #1, #2", "",
        "SPN を持つサービスアカウントがドメインに必要（既定のラボには無いので作る）"),
    "ServicePrincipalNames Discovery with SetSPN": (
        "setspn.exe でドメインの SPN を列挙したことを検知する",
        "T1558.003 #3", "CIM", ""),
    "Rubeus Command Line Parameters": (
        "Rubeus 特有のコマンドライン引数（kerberoast / asreproast / ptt など）を検知する",
        "T1558.003 #2, T1558.004 #1", "CIM", ""),
    "Kerberos Pre-Authentication Flag Disabled in UserAccountControl": (
        "ユーザーの「Kerberos 事前認証を要求しない」が有効にされたことを検知する（4738）",
        "", "",
        "AS-REP Roasting の下準備。DC の「Active Directory ユーザーとコンピューター」でフラグを付けて再現する"),
    "Detect Password Spray Attempts": (
        "1 つの送信元からの認証失敗が統計的に多いこと（パスワードスプレー）を検知する",
        "T1110.003 #1, #2", "CIM",
        "3 シグマ判定なので、平常時の認証ログがある程度たまってから試す"),
    "Windows Multiple Users Failed To Authenticate Using Kerberos": (
        "1 つの送信元から 30 以上のユーザーで Kerberos 事前認証に失敗したことを検知する（4771）",
        "T1110.003 #2", "",
        "しきい値が 30 ユーザーなので、ドメインにユーザーを 30 以上作っておく必要がある"),
    "Enable WDigest UseLogonCredential Registry": (
        "WDigest の UseLogonCredential を 1 にして平文の資格情報をメモリに残す設定変更を検知する",
        "", "CIM", "レジストリ変更は Sysmon 13。手動でレジストリを変更して再現する"),
    # ---------------- 偵察 ----------------
    "Domain Controller Discovery with Nltest": (
        "nltest の /dclist: / /dsgetdc: で DC を探したことを検知する",
        "T1018 #3", "CIM", "Caldera の Discovery でも実行される（2026-11-01 確認）"),
    "NLTest Domain Trust Discovery": (
        "nltest の /domain_trusts / /all_trusts でドメインの信頼関係を調べたことを検知する",
        "T1482 #2", "CIM", ""),
    "DSQuery Domain Discovery": (
        "dsquery で trustedDomain を問い合わせたことを検知する",
        "T1482 #1", "CIM", ""),
    "Windows AdFind Exe": (
        "AdFind.exe の実行（AD の列挙ツール）を検知する",
        "T1018 #10, #11", "CIM", ""),
    "Domain Account Discovery with Wmic": (
        "wmic で LDAP 名前空間からドメインユーザーを列挙したことを検知する",
        "", "CIM", "対応する ART テストが無いので手動で再現する"),
    "Get DomainUser with PowerShell Script Block": (
        "PowerView の Get-DomainUser の実行を検知する（4104）",
        "T1087.002 #11", "", ""),
    "GetDomainGroup with PowerShell Script Block": (
        "PowerView の Get-DomainGroup の実行を検知する（4104）",
        "T1069.002 #13", "", ""),
    "Elevated Group Discovery With Wmic": (
        "wmic で Domain Admins などの特権グループを列挙したことを検知する",
        "", "CIM", "対応する ART テストが無いので手動で再現する"),
    "PowerShell Domain Enumeration": (
        "Get-ADDomain / Get-ADGroupMember などドメイン列挙のコマンドレットを検知する（4104）",
        "T1087.002 #11, T1482 #6", "", ""),
    "Detect SharpHound Usage": (
        "SharpHound.exe（BloodHound の収集ツール）の実行を検知する",
        "T1059.001 #2, T1069.001 #4", "CIM", ""),
    "Detect SharpHound Command-Line Arguments": (
        "SharpHound の -collectionMethod / Invoke-BloodHound を検知する",
        "T1059.001 #2, #3", "CIM", ""),
    "Check Elevated CMD using whoami": (
        "whoami /groups の結果を find で絞り、管理者権限（12288）か確かめる動きを検知する",
        "", "CIM", "FIN7 の手口。手動で再現する"),
    "Windows File Share Discovery With Powerview": (
        "PowerView の Invoke-ShareFinder の実行を検知する（4104）",
        "T1135 #8", "", ""),
    # ---------------- 実行・防御回避 ----------------
    "Malicious PowerShell Process With Obfuscation Techniques": (
        "難読化の特徴（記号の多用など）を持つ PowerShell のコマンドラインを検知する",
        "T1027 #7, T1027 #11", "CIM", "Caldera の base64 難読化でも狙える"),
    "Powershell Fileless Script Contains Base64 Encoded Content": (
        "スクリプト内の FromBase64String（base64 のデコード）を検知する（4104）",
        "T1027 #2", "", "正規のスクリプトでも使われるので誤検知が出やすい"),
    "Detect Mimikatz With PowerShell Script Block Logging": (
        "スクリプト内の mimikatz / sekurlsa / kerberos::golden などの文字列を検知する（4104）",
        "T1059.001 #1", "", ""),
    "Windows PowerShell Script Block With Malicious String": (
        "攻撃ツールでよく使う文字列を含むスクリプトを検知する（4104）",
        "T1059.001 #1, #3", "", ""),
    "Unloading AMSI via Reflection": (
        "リフレクションで AMSI（マルウェア対策のスキャン機能）を無効化するスクリプトを検知する（4104）",
        "T1685 #16", "", ""),
    "Windows Suspicious Process File Path": (
        "C:\\Users\\Public や C:\\PerfLogs など、通常プログラムを置かない場所からの実行を検知する",
        "T1036.005 #4", "CIM",
        "Caldera の C:\\Temp\\splunkd.exe は、ルールが \\temp\\ を除外しているので当たらない"),
    "Windows LOLBAS Executed Outside Expected Path": (
        "LOLBAS（OS 標準の悪用されやすいツール）を本来と違う場所にコピーして実行したことを検知する",
        "T1036.005 #2, #3", "CIM", ""),
    "Attacker Tools On Endpoint": (
        "攻撃ツールの一覧（ルックアップ）にあるプロセス名の実行を検知する",
        "T1003.001 #1, T1059.001 #2", "CIM", "procdump や SharpHound なども一覧に含まれる"),
    "Suspicious Rundll32 no Command Line Arguments": (
        "引数なしの rundll32.exe の実行（プロセスインジェクションの踏み台によくある）を検知する",
        "", "CIM", "Cobalt Strike の典型。ART に直接のテストは無いので手動で再現する"),
    "Detect Rundll32 Inline HTA Execution": (
        "rundll32 に javascript: / vbscript: を渡したインライン実行を検知する",
        "T1218.011 #1, #2", "CIM", ""),
    "Suspicious mshta child process": (
        "mshta.exe から powershell や cmd などが起動したことを検知する",
        "T1218.005 #2, #10", "CIM", ""),
    "Windows Event Log Cleared": (
        "セキュリティログ（1102）やシステムログ（104）が消去されたことを検知する",
        "T1685.005 #1, #2", "", "ART の旧番号は T1070.001"),
    "Disable Logs Using WevtUtil": (
        "wevtutil でイベントログを無効化・消去したことを検知する",
        "T1685.001 #6", "CIM", "ART の旧番号は T1562.002 / T1070.001"),
    "Unload Sysmon Filter Driver": (
        "fltMC で Sysmon のドライバーをアンロードして、Sysmon の記録を止めたことを検知する",
        "T1685 #14", "CIM",
        "SOC 的に最重要。成功すると以降の Sysmon ログが止まるので、テストのあとに Sysmon を戻す"),
    "Windows Attempt To Stop Security Service": (
        "net / sc でセキュリティ製品のサービスを停止しようとしたことを検知する",
        "T1685 #18, #24", "CIM", ""),
    "Add or Set Windows Defender Exclusion": (
        "Add-MpPreference / Set-MpPreference で Defender の除外を追加したことを検知する",
        "T1685 #26, #27, #28", "CIM", "Server に Defender が無くても、コマンドの実行は記録される"),
    "Disable AMSI Through Registry": (
        "レジストリの AmsiEnable を 0 にして AMSI を無効化したことを検知する",
        "T1685 #56", "CIM", ""),
    # ---------------- 永続化・権限 ----------------
    "Windows Scheduled Task with Highest Privileges": (
        "schtasks で /rl highest（最上位の特権）付きのタスクを作成したことを検知する",
        "", "CIM",
        "schtasks.exe のコマンドラインだけを見ている。Caldera エージェントのタスクは Ansible が API で登録するので当たらない見込み"),
    "WinEvent Scheduled Task Created Within Public Path": (
        "Public / ProgramData / Temp などのパスを実行するスケジュールタスクの登録を検知する（4698）",
        "T1053.005 #2, #4", "",
        "Caldera エージェントのタスク（C:\\Temp\\splunkd.exe）が build のたびに当たる（ラボ固有の誤検知）"),
    "Scheduled Task Deleted Or Created via CMD": (
        "schtasks の /create / /delete を検知する",
        "T1053.005 #1, #2", "CIM", ""),
    "Windows Schtasks Create Run As System": (
        "schtasks で /ru system（SYSTEM 権限で実行）のタスクを作成したことを検知する",
        "T1053.005 #1", "CIM", "テストのコマンドに /ru system が入っているかは実行前に -ShowDetails で確認する"),
    "Sc exe Manipulating Windows Services": (
        "sc.exe でサービスを作成・変更したことを検知する",
        "T1543.003 #2", "CIM", ""),
    "Windows Service Creation on Remote Endpoint": (
        "sc.exe \\\\<リモート> create でリモートの端末にサービスを作成したことを検知する",
        "T1543.003 #5", "CIM", ""),
    "Registry Keys Used For Persistence": (
        "Run / RunOnce など自動起動用のレジストリキーの変更を検知する",
        "T1547.001 #1, #2, #3", "CIM", ""),
    "Detect New Local Admin account": (
        "新しいユーザーの作成（4720）と Administrators への追加（4732）が続いたことを検知する",
        "T1136.001 #8", "", ""),
    "Windows AD Privileged Group Modification": (
        "Domain Admins など特権の AD グループへのメンバー追加を検知する（4728）",
        "T1098 #2", "", "DC で実行"),
    "Windows AD add Self to Group": (
        "ユーザーが自分自身を AD グループに追加したことを検知する（4728）",
        "", "", "DC で、追加する人と追加される人を同じアカウントにして手動で再現する"),
    # ---------------- 横展開 ----------------
    "Detect PsExec With accepteula Flag": (
        "PsExec に -accepteula を付けて実行したことを検知する",
        "T1021.002 #3", "CIM", ""),
    "Impacket Lateral Movement Commandline Parameters": (
        "Impacket（smbexec / atexec など）が作る特徴的な cmd.exe のコマンドラインを検知する",
        "T1047 #11", "CIM", "Impacket は Python のツール。Linux 側から実行する"),
    "Impacket Lateral Movement WMIExec Commandline Parameters": (
        "wmiprvse.exe から起動した、wmiexec 特有の cmd.exe のコマンドラインを検知する",
        "T1047 #11", "CIM", ""),
    "Executable File Written in Administrative SMB Share": (
        "管理共有（C$ / ADMIN$）に .exe / .dll を書き込んだことを検知する（5145）",
        "T1021.002 #3", "", "5145 は advanced_logging の「詳細なファイル共有」監査で出る"),
    "Remote Process Instantiation via WMI": (
        "wmic /node: でリモートの端末にプロセスを作成したことを検知する",
        "T1047 #6", "CIM", ""),
    "Remote Process Instantiation via WinRM and PowerShell": (
        "Invoke-Command -ComputerName でリモートの端末にコマンドを実行したことを検知する",
        "T1021.006 #2", "CIM", ""),
    "Wsmprovhost LOLBAS Execution Process Spawn": (
        "WinRM のホストプロセス（wsmprovhost.exe）から LOLBAS（rundll32 / mshta など）が直接起動したことを検知する",
        "T1021.006 #2", "CIM",
        "ART の simulate は WinRM 経由だが、wsmprovhost の直下は powershell.exe（一覧に無い）なので、常に発火するわけではない。テストのバイナリが直下に来たときだけ当たる"),
    "Windows Remote Services Rdp Enable": (
        "レジストリの fDenyTSConnections を 0 にして RDP を有効化したことを検知する",
        "", "CIM", "手動でレジストリを変更して再現する"),
    "Windows RDP Login Session Was Established": (
        "RDP でのログオン（4624、ログオンの種類 10）を検知する",
        "", "", "RDP で入るだけで発火する"),
    "Windows Remote Desktop Network Bruteforce Attempt": (
        "1 時間以内に 3389 番への接続が 10 回を超えたこと（RDP の総当たり）を検知する（Sysmon 3）",
        "", "CIM",
        "SPL の values(Al_Traffic.src_port) は All_Traffic のタイプミス（src_port が空になるだけで、発火には影響しない）。RDP のログイン失敗を手で繰り返して再現する"),
    "Windows Special Privileged Logon On Multiple Hosts": (
        "同じユーザーが 5 分以内に 30 台以上へ特権ログオン（4672）したことを検知する",
        "", "",
        "しきい値 30 台に対してラボは Windows 4 台なので、そのままでは発火しない。試すならしきい値を 3 に下げたコピーを作る"),
    # ---------------- ツールの持ち込み ----------------
    "Windows File Download Via CertUtil": (
        "certutil の -urlcache / -verifyctl でファイルをダウンロードしたことを検知する",
        "T1105 #7, #8", "CIM", ""),
    "BITSAdmin Download File": (
        "bitsadmin の /transfer でファイルをダウンロードしたことを検知する",
        "T1105 #9", "CIM", ""),
    "Windows Curl Download to Suspicious Path": (
        "curl.exe で AppData / ProgramData / Public などにファイルを保存したことを検知する",
        "T1105 #18", "CIM", "保存先が対象のパスになるかは、テストの引数で確認する"),
    # ---------------- Linux ----------------
    "Linux Decode Base64 to Shell": (
        "base64 でデコードした内容をシェルにパイプで渡したことを検知する",
        "T1027 #1", "CIM", "Linux は Sysmon for Linux（sysmon:linux）のプロセスログを使う"),
    "Linux Curl Upload File": (
        "curl の -F / --upload-file / -d などでファイルを外部に送ったことを検知する",
        "", "CIM", "ルールは AWS の認証情報ファイルの送信を想定。手動で再現する"),
    "Linux Ingress Tool Transfer with Curl": (
        "curl の -O / --output などでスクリプトやバイナリをダウンロードしたことを検知する",
        "T1105 #27", "CIM", ""),
    "Linux NOPASSWD Entry In Sudoers File": (
        "sudoers に NOPASSWD のエントリを書き込むコマンドを検知する",
        "", "CIM", "手動で再現する"),
    "Linux Auditd Sudo Or Su Execution": (
        "sudo / su の実行を検知する（auditd）",
        "T1548.003 #1", "AUDITD", ""),
    "Linux Find Privilege Escalation": (
        "sudo 付きの find -exec（GTFOBins の代表的な権限昇格）を検知する",
        "", "CIM", "手動で再現する"),
    "Linux Add Files In Known Crontab Directories": (
        "/etc/cron* や /var/spool/cron にファイルが作られたことを検知する",
        "T1053.003 #1, #3", "CIM", "ファイル作成のログ（Sysmon for Linux の 11）が前提"),
    "Linux Auditd Add User Account": (
        "useradd / adduser でユーザーを作成したことを検知する（auditd）",
        "T1136.001 #1", "AUDITD", ""),
    "Linux SSH Authorized Keys Modification": (
        "authorized_keys を書き換えるコマンドを検知する",
        "T1098.004 #1", "CIM", ""),
    "Linux Possible Access Or Modification Of sshd Config File": (
        "cat / vi などで sshd_config を開いたことを検知する",
        "", "CIM", "手動で再現する"),
    "Linux SSH Remote Services Script Execute": (
        "ssh の -o StrictHostKeyChecking などを付けて、リモートでスクリプトを実行したことを検知する",
        "", "CIM", "SSH で入って手動で再現する"),
    "Linux Auditd Whoami User Discovery": (
        "whoami の実行を検知する（auditd）",
        "T1033 #2", "AUDITD", ""),
    # ---------------- ネットワーク（Palo 前提） ----------------
    "Internal Horizontal Port Scan": (
        "内部の 1 台が、同じポートで 250 以上の宛先に通信したこと（横方向のスキャン）を検知する", "", "PALO", ""),
    "Internal Vertical Port Scan": (
        "内部の 1 台が、1 つの宛先の 500 以上のポートに通信したこと（縦方向のスキャン）を検知する", "", "PALO", ""),
    "Internal Horizontal Port Scan NMAP Top 20": (
        "nmap の上位 20 ポートで、250 以上の宛先に通信したことを検知する", "", "PALO", ""),
    "Internal Vulnerability Scan": (
        "内部からの脆弱性スキャン（IDS の検知が多数の宛先に出る）を検知する", "", "PALO", "ESCU 側で EXPERIMENTAL 扱い"),
    "Protocols passing authentication in cleartext": (
        "Telnet / FTP / POP3 など平文で認証するプロトコルの通信を検知する", "", "PALO", ""),
    "Remote Desktop Network Traffic": (
        "普段 RDP を使わない端末どうしの 3389 番の通信を検知する", "", "PALO", ""),
    "SMB Traffic Spike": (
        "SMB（139 / 445）の通信量が普段より急に増えたことを検知する", "", "PALO", "ESCU 側で EXPERIMENTAL 扱い"),
    "Protocol or Port Mismatch": (
        "ポートとアプリが合わない通信（80 番で HTTP 以外など）を検知する", "", "PALO", ""),
    "Prohibited Network Traffic Allowed": (
        "禁止しているポート（ルックアップで定義）の通信が許可されていたことを検知する",
        "", "PALO", "ルックアップ lookup_interesting_ports の定義が必要"),
    "Windows AD Replication Service Traffic": (
        "DC 以外からの AD 複製（DRSUAPI）の通信を検知する", "", "PALO", "ESCU 側で EXPERIMENTAL 扱い"),
    "Detect Remote Access Software Usage Traffic": (
        "AnyDesk / TeamViewer などリモートアクセスソフトの通信を検知する（Palo の App-ID）", "", "PALO", ""),
    "Detect Large ICMP Traffic": (
        "外部宛ての 1,000 バイトを超える ICMP 通信（ICMP トンネルなど）を検知する", "", "PALO", ""),
    "TOR Traffic": (
        "TOR の通信が許可されていたことを検知する（Palo の App-ID）", "", "PALO", ""),
    "Detect Remote Access Software Usage URL": (
        "リモートアクセスソフトの URL へのアクセスを検知する（Palo の URL フィルタリングのログ）", "", "PALO", ""),
    "Detect Outbound LDAP Traffic": (
        "外部の IP への LDAP（389 / 636）通信を検知する（Log4Shell の JNDI など）", "", "PALO", "Hunting（定期実行ではなく調査用）"),
}
