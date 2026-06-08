# AegisProbe 绾搁潰鑳藉姏璇勪及鎶ュ憡 v2.2

> 璇勪及鏃ユ湡: 2025-07  
> 璇勪及鏂规硶: PTES 7 闃舵閫愰」璇勫垎 (0-10)  
> 璇勪及鑰? 缁煎悎浠ｇ爜瀹℃煡 + 鏋舵瀯鍒嗘瀽 + 绔炲搧瀵规瘮

---

## 涓€銆佺患鍚堣瘎鍒?
```
PTES Phase 1 (鍓嶆湡浜や簰):     鈻堚枅鈻戔枒鈻戔枒鈻戔枒鈻戔枒  2/10
PTES Phase 2 (淇℃伅鏀堕泦):     鈻堚枅鈻堚枅鈻堚枅鈻堚枒鈻戔枒  7/10  鈫?鏈€寮?PTES Phase 3 (濞佽儊寤烘ā):     鈻堚枅鈻堚枅鈻戔枒鈻戔枒鈻戔枒  5/10  鈫?鏀诲嚮閾惧紩鎿庡崌绾?PTES Phase 4 (婕忔礊鍒嗘瀽):     鈻堚枅鈻堚枅鈻堚枅鈻堚枒鈻戔枒  7/10  鈫?寮洪」
PTES Phase 5 (婕忔礊鍒╃敤):     鈻堚枅鈻堚枒鈻戔枒鈻戔枒鈻戔枒  3/10  鈫?绾搁潰锛屾湭楠岃瘉
PTES Phase 6 (鍚庢笚閫?:       鈻戔枒鈻戔枒鈻戔枒鈻戔枒鈻戔枒  0/10  鈫?缂哄け
PTES Phase 7 (鎶ュ憡):         鈻堚枅鈻堚枅鈻戔枒鈻戔枒鈻戔枒  4/10

PTES 鍔犳潈缁煎悎:               4.3/10 (v2.2 鏀诲嚮閾惧紩鎿庡崌绾?+0.2)
```

**瀹氭€у垽鏂?*: AegisProbe v2.2 鏄竴涓?*浼樼鐨勪俊鎭敹闆嗗拰婕忔礊鍒嗘瀽寮曟搸**锛岄厤浜嗕竴涓?*绾搁潰涓婂畬鏁翠絾浠庢湭楠岃瘉杩囩殑鍒╃敤妗嗘灦**锛屽畬鍏ㄦ病鏈夊悗娓楅€忚兘鍔涖€?
---

## 浜屻€佸垎闃舵璇︾粏璇勪及

### Phase 1: 鍓嶆湡浜や簰 鈥?2/10

| 鑳藉姏 | 璇勫垎 | 鐜扮姸 | 闂 |
|------|------|------|------|
| 鑼冨洿瀹氫箟 | 5 | `createDefaultPentestScope()` 鏀寔鐧藉悕鍗?榛戝悕鍗?閫熺巼闄愬埗 | 浠?CLI 鍙傛暟锛屾棤鎸佷箙鍖?RoE 鏂囨。 |
| 鎺堟潈纭 | 3 | `--yes` 璺宠繃鎺堟潈鎻愮ず | 鏃犳寮?RoE 鐢熸垚锛屾棤娉曞緥鍏嶈矗澹版槑 |
| 瀹㈡埛娌熼€?| 0 | 鏃?| 鏃犻潰鍚戝鎴风殑浜や簰鐣岄潰鎴栬繘搴︽姤鍛?|

### Phase 2: 淇℃伅鏀堕泦 鈥?7/10

| 鑳藉姏 | 璇勫垎 | 鐜扮姸 | 闂 |
|------|------|------|------|
| 瀛愬煙鍚嶆灇涓?| 8 | subfinder + amass + assetfinder + dnsx | 鈥?|
| 绔彛鎵弿 | 8 | nmap 鍏ㄩ噺 TCP+UDP + naabu 蹇€熸壂鎻忥紝NSE 鑴氭湰闆嗘垚 | nmap 瓒呮椂 300s 瀵瑰ぇ鍨嬬洰鏍囧彲鑳戒笉澶?|
| 鏈嶅姟鎺㈡祴 | 8 | httpx + whatweb + wappalyzer + nuclei tech-detect | 鈥?|
| 鍓嶇鐖彇 | 7 | katana + gau + waybackurls + gospider + subjs | JS 鍒嗘瀽鏄潤鎬佹鍒欙紝鏈В鏋?AST |
| OSINT | 2 | FOFA 浠呭瓙鍩熷悕/IP | 鏃犱汉鍛?缁勭粐/閭鏋氫妇锛屾棤 Google dorking/Shodan/Censys |
| 璁惧璇嗗埆 | 7 | DeviceProfileDB 15 绉嶈澶?| 渚濊禆 nmap 杈撳嚭璐ㄩ噺锛岃鍖归厤鍙兘 |
| 鎼滅储寮曟搸鍙戠幇 | 2 | gau/waybackurls 琚姩 | 鏃犱富鍔?Google/Bing 鎼滅储 |

### Phase 3: 濞佽儊寤烘ā 鈥?4/10

| 鑳藉姏 | 璇勫垎 | 鐜扮姸 | 闂 |
|------|------|------|------|
| 鏀诲嚮闈㈠垎鏋?| 6 | `buildSecurityAssetGraph()` + `SecurityDecisionQueue` | 鍥炬槸闈欐€佸揩鐓э紝涓嶆槸鍔ㄦ€佹敾鍑婚潰 |
| 鏀诲嚮璺緞瑙勫垝 | 6 | `ATTACK_CHAINS_V2` 50+ 鏉＄粨鏋勫寲瑙勫垯, 5 绉嶆潯浠剁被鍨? OR/AND 閫昏緫, MITRE ATT&CK 鏄犲皠 | 瑙勫垯鍩轰簬闈欐€佹潯浠? 鏃犲姩鎬佹敾鍑诲浘鎺ㄧ悊 (MulVAL/CALDERA 绛夌骇) |
| 涓氬姟褰卞搷璇勪及 | 3 | `buildSecurityObjectiveModel()` | admin/control-plane/server-risk 涓夌被锛岀矑搴︾矖 |
| CVE 浼樺厛绾?| 8 | CVSS + EPSS + KEV + CPE 璇箟 | 浜偣锛屼絾 EPSS 渚濊禆缃戠粶 (鍙€? |
| 鍋囪鐢熸垚 | 6 | Graph Hypothesis + Reason 浠诲姟 | 渚濊禆 LLM 鎺ㄧ悊璐ㄩ噺 |

### Phase 4: 婕忔礊鍒嗘瀽 鈥?7/10

| 鑳藉姏 | 璇勫垎 | 鐜扮姸 | 闂 |
|------|------|------|------|
| CVE 鍖归厤 | 8 | CPE 2.3 + semver + NVD + nuclei 绱㈠紩 | 鈥?|
| OWASP Top 10 | 7 | 10 绫诲埆 脳 nuclei 鐪熷疄鏍囩 + curl | nuclei 妯℃澘缁撴灉鏈獙璇佸氨鍐欏叆鎶ュ憡 |
| 寮卞彛浠ゆ祴璇?| 5 | DeviceProfileDB 榛樿鍑嵁 | 鍙敓鎴愬缓璁紝鏈嚜鍔ㄦ墽琛?weak password spray |
| 閰嶇疆瀹℃煡 | 6 | nuclei misconfig/exposure + curl 妫€鏌?| 鈥?|
| 涓氬姟閫昏緫 | 3 | `buildBusinessLogicTestPlan()` 鐢熸垚璁″垝 | 瀹為檯鎵ц闇€瑕佷汉宸?|
| 璇姤澶勭悊 | 2 | `parseOwaspTestOutput()` 鍏抽敭璇嶅尮閰?| 鏃犵湡姝ｇ殑璇姤杩囨护鏈哄埗 |

### Phase 5: 婕忔礊鍒╃敤 鈥?3/10

| 鑳藉姏 | 璇勫垎 | 鐜扮姸 | 闂 |
|------|------|------|------|
| Metasploit | 4 | MsfRpcClient 浠ｇ爜瀹屾暣 (MessagePack RPC) | **浠庢湭鍦ㄧ湡瀹?msfrpcd 涓婃祴璇曡繃** |
| SQL 娉ㄥ叆 | 4 | SqlmapAdapter REST API + CLI | **鏈祴璇曡繃 sqlmap --api 妯″紡** |
| nuclei exploit | 5 | nuclei exploit 妯℃澘鎵ц | 渚濊禆妯℃澘璐ㄩ噺 |
| Payload 鐢熸垚 | 6 | 12 CVE 鍏蜂綋 payload + `generatePayload()` | 鈥?|
| 鑷畾涔夊埄鐢?| 3 | CustomScriptRunner | 鏃犲畨鍏ㄦ矙绠?|
| 楠岃瘉闂幆 | 2 | 缁撴灉鍥炲啓 Graph | parseOwaspTestOutput 鍙槸鍏抽敭璇嶅尮閰?|

### Phase 6: 鍚庢笚閫?鈥?0/10

| 鑳藉姏 | 璇勫垎 | 璇存槑 |
|------|------|------|
| 鏉冮檺鎻愬崌 | 0 | 鏃?sudo -l/SUID/cron/kernel exploit 鑷姩鍖?|
| 鍑嵁鎻愬彇 | 0 | 鏃?mimikatz/hashdump/lsass 闆嗘垚 |
| 妯悜绉诲姩 | 0 | 鏃?psexec/wmi/ssh 闅ч亾/绔彛杞彂 |
| 鎸佷箙鍖?| 0 | 鏃?|
| 鏁版嵁澶栦紶 | 0 | 鏃?|

### Phase 7: 鎶ュ憡 鈥?4/10

| 鑳藉姏 | 璇勫垎 | 鐜扮姸 | 闂 |
|------|------|------|------|
| 鎶€鏈姤鍛?| 6 | Markdown, 瑕嗙洊 findings/CVE/assets/evidence | 鈥?|
| OWASP 瑕嗙洊 | 6 | `buildOwaspCoverageReport()` 4 鎬佽仛鍚?| 鈥?|
| 璇佹嵁绱㈠紩 | 5 | SQLite 25+ 琛?| 鈥?|
| 淇寤鸿 | 3 | finding.remediation | LLM 鐢熸垚鍐呭鏈粡浜哄伐瀹℃牳 |
| 鎵ц鎽樿 | 0 | 鏃?| 娌℃湁 CTO 鍙鐨勬憳瑕?|
| HTML/PDF | 0 | 鍙湁 Markdown | 瀹㈡埛涓嶆帴鍙?|

---

## 涓夈€?0 涓殣钘忛棶棰?(瓒呭嚭琛ㄩ潰璇勫垎)

### H1. 宸ュ叿鎵ц缂轰箯骞傜瓑鎬т繚璇?澶氭杩愯鍚屼竴涓伐鍏凤紙濡?nmap锛夊彲鑳戒骇鐢熶笉鍚岀殑杈撳嚭銆傜幇鏈変唬鐮佹病鏈夊幓閲嶆満鍒讹紝閲嶅鎵弿浼氭薄鏌?Graph銆?
### H2. LLM 涓婁笅鏂囩獥鍙ｅ彲鑳芥孩鍑?`buildGraphContextPrompt()` 鏈?4000 瀛楃鎴柇锛屼絾瀵逛簬澶х洰鏍囷紝Graph 鍙兘鍖呭惈 100+ evidence 鑺傜偣銆傛埅鏂細涓㈠け鍏抽敭鍙戠幇銆?
### H3. 瀛?Agent 瓒呮椂澶勭悊涓嶅畬鍠?`subagent-runtime.ts` 鏈?25 娆¤凯浠ｄ笂闄愶紝浣嗘病鏈夊熀浜庣洰鏍囧鏉傚害鐨勫姩鎬佽秴鏃躲€傜畝鍗曠洰鏍囧拰澶嶆潅鐩爣鐢ㄥ悓鏍风殑杩唬棰勭畻銆?
### H4. 骞跺彂瀹夊叏
澶氫釜瀛?Agent 鍚屾椂鍐欏叆 Graph 鏃讹紝`graphCache` 鏄唴瀛?Map锛屾棤閿佷繚鎶ゃ€傚苟鍙?`addEvidence()` 鍙兘涓㈠け鑺傜偣銆?
### H5. SQLite 鍐欏叆绔炰簤
`AuditStore` 鐨?SQLite 杩炴帴鍦?Node.js 涓槸鍗曠嚎绋嬬殑锛屼絾澶氫釜瀛?Agent 鍚屾椂璋冪敤 `store.addEvidence()` 鍙兘瀵艰嚧 SQLITE_BUSY銆?
### H6. Payload 鐢熸垚鏈€冭檻鐩爣 OS/鏋舵瀯
旧的 `CVE_PAYLOAD_MAP` 已移除；CVE chain 现在只输出优先级、验证引用和 payload workbench 指引，具体 payload 由 `payload_candidates`/`payload_request_drafts` 基于当前证据生成。
### H7. RateController 鏄潤鎬佺殑
5 妗ｉ€熺巼 (stealth/slow/normal/fast/aggressive) 涓嶄細鏍规嵁 WAF 鍙嶉鑷姩鍒囨崲銆傝 ban 鍚庝笉浼氳嚜鍔ㄩ檷閫熴€?
### H8. nuclei 妯℃澘鐗堟湰涓嶅尮閰?`matchNucleiKnowledgeForTechnologies` 妫€鏌?`templateCompatibleWithObservedVersion`锛屼絾濡傛灉 nuclei 妯℃澘鏇存柊浜嗕絾鏈湴绱㈠紩鏈悓姝ワ紝鍙兘婕忔姤銆?
### H9. 鏃犲洖婊氭満鍒?鍒╃敤澶辫触鍚?(`MsfRpcClient.module.execute`)锛屾病鏈夋竻鐞?metasploit jobs/sessions 鐨勬満鍒躲€傚彲鑳界暀涓嬪鍎胯繘绋嬨€?
### H10. 鏃犵绾挎ā寮忎笅鐨勯檷绾х瓥鐣?寰堝鍔熻兘渚濊禆澶栭儴 API (NVD/EPSS/FOFA/KEV)銆傚鏋滃叏閮ㄤ笉鍙敤锛岀郴缁熷簲璇ユ槑纭檷绾т负"绾湰鍦版ā寮?锛屼絾褰撳墠浠ｇ爜鏃犳閫昏緫銆?
---

## 鍥涖€佷笌绔炲搧鐨勫瑙傚樊璺?
| 缁村害 | AegisProbe v2.2 | PentestGPT | Cairn | 鍟嗕笟娓楅€忔祴璇?|
|------|----------------|------------|-------|------------|
| 鍩哄噯楠岃瘉 | 鉂?0 闈舵満 | 鉁?104 XBOW (86.5%) | 鉁?54/54 CTF AK | 鉁?瀹㈡埛椤圭洰 |
| 鍚庢笚閫?| 鉂?| 鉂?| 鉂?| 鉁?|
| 鍒╃敤楠岃瘉 | 鈿狅笍 浠ｇ爜瀛樺湪鏈祴璇?| 鈿狅笍 閮ㄥ垎 | 鉁?CTF 鐜 | 鉁?|
| 鎶ュ憡 | 鈿狅笍 Markdown | 鉁?HTML/PDF | 鉂?| 鉁?鍟嗕笟鏍煎紡 |
| 瀹瑰櫒闅旂 | 鉂?| 鉁?Docker | 鉁?Docker | 鉁?|
| 璇姤澶勭悊 | 鉂?鍏抽敭璇嶅尮閰?| 鈿狅笍 鎵嬪姩楠岃瘉 | 鉁?CTF (flag 楠岃瘉) | 鉁?浜哄伐瀹℃牳 |
| 骞跺彂瀹夊叏 | 鈿狅笍 鏈祴璇?| 鉁?| 鉁?ThreadPoolExecutor | 鉁?|
| 閫熺巼鑷€傚簲 | 鉂?闈欐€?| 鉂?| 鉁?OODA 鍙嶉 | 鉁?|

---

## 浜斻€佺湡瀹炴笚閫忚缁冭鍒?
### 鐩爣
鍦ㄥ彈鎺х幆澧冧腑楠岃瘉 AegisProbe 鐨勭鍒扮娓楅€忚兘鍔涳紝鍙戠幇骞朵慨澶嶄唬鐮佸眰闈㈡棤娉曟毚闇茬殑闂銆?
### 闃舵 A: 鍗曞厓楠岃瘉 (Week 1)

**A1. Metasploit RPC 鑱旈€氭€ф祴璇?*
- 鍦?Docker 涓惎鍔?`msfrpcd -U msf -P test -p 55553`
- 楠岃瘉 `MsfRpcClient.login()` 鈫?`module.exploits()` 鈫?`module.search()` 鈫?`module.execute()`
- 淇: API 鐗堟湰涓嶅尮閰嶃€丮essagePack 缂栫爜閿欒銆佽秴鏃惰缃?
**A2. sqlmap REST API 娴嬭瘯**
- `sqlmap --api` 鍚姩 鈫?`SqlmapAdapter.scan()` 鈫?杞 `/scan/<id>/log`
- 鍦?DVWA (Damn Vulnerable Web App) SQLi 绔偣涓婇獙璇?- 淇: API 璺緞宸紓銆佸搷搴旇В鏋愰敊璇?
**A3. nuclei exploit 妯℃澘楠岃瘉**
- 閫夊彇 5 涓?CVE 妯℃澘 (CVE-2021-41773, CVE-2021-44228, CVE-2022-26134, CVE-2024-4577, CVE-2022-1388)
- 鍦ㄥ搴旂増鏈殑鏈嶅姟涓婇獙璇佹ā鏉跨‘瀹炶兘妫€娴?- 淇: 妯℃澘璺緞閿欒銆佹ā鏉跨増鏈笉鍖归厤

### 闃舵 B: 闈舵満娓楅€?(Week 2)

**B1. DVWA (Damn Vulnerable Web App)**
- 鐩爣: 瀹屾暣 PTES 娴佺▼
- 楠岃瘉鐐? SQLi + XSS + CSRF + Command Injection 妫€娴嬪拰鍒╃敤
- 棰勬湡: 鑷姩瀹屾垚 80% 鐨勬紡娲炲彂鐜?
**B2. Metasploitable 2**
- 鐩爣: 澶氭湇鍔℃笚閫?(FTP/SMB/SSH/HTTP/MySQL)
- 楠岃瘉鐐? 绔彛鎵弿 鈫?鏈嶅姟璇嗗埆 鈫?CVE 鍖归厤 鈫?鍒╃敤 鈫?鍚庢笚閫?- 棰勬湡: 鍙戠幇 15+ 婕忔礊锛屾垚鍔熷埄鐢ㄨ嚦灏?3 涓?
**B3. VulnHub 闈舵満 (閫?3 涓笉鍚岄毦搴?**
- 绠€鍗? Kioptrix Level 1
- 涓瓑: SickOS 1.2
- 鍥伴毦: 鑷€?- 楠岃瘉鐐? 绔埌绔笚閫忥紝浠庝俊鎭敹闆嗗埌 root shell

### 闃舵 C: 鍘嬪姏娴嬭瘯 (Week 3)

**C1. 澶ц妯＄洰鏍囨壂鎻?*
- 鐩爣: hackthebox 鎴?tryhackme 涓婄殑 5 涓椿璺冮澏鏈?- 楠岃瘉鐐? Graph 鎵╁睍鎬с€丩LM 涓婁笅鏂囩獥鍙ｃ€丼QLite 骞跺彂

**C2. WAF 鐜娴嬭瘯**
- 鍦?Cloudflare/ModSecurity 鍚庨潰閮ㄧ讲 DVWA
- 楠岃瘉鐐? RateController 鑷姩闄嶉€熴€乄AF 缁曡繃绛栫暐

**C3. 闀挎椂闂磋繍琛屾祴璇?*
- 72 灏忔椂鎸佺画鎵弿
- 楠岃瘉鐐? 鍐呭瓨娉勬紡銆丼QLite WAL 鏂囦欢澧為暱銆佸瓙 Agent 鍍靛案杩涚▼

### 闃舵 D: 淇涓庝紭鍖?(Week 4)

**D1. 淇闃舵 A-C 鍙戠幇鐨勬墍鏈夐棶棰?*
**D2. 琛ュ叏鍚庢笚閫忔ā鍧?* (sudo -l, SUID, 鍑嵁鎻愬彇)
**D3. 瀹炵幇 HTML/PDF 鎶ュ憡鐢熸垚**
**D4. 娣诲姞瀹瑰櫒闅旂鍔熻兘**

---

## 鍏€佹敼杩涜矾绾垮浘 (鎸変紭鍏堢骇)

| # | 鏀硅繘椤?| 绫诲瀷 | 浼樺厛绾?| 棰勪及 |
|---|--------|------|--------|------|
| 1 | 鍦ㄧ湡瀹為澏鏈轰笂楠岃瘉鍒╃敤寮曟搸 (A1-A3) | 楠岃瘉 | 馃敶 P0 | 3澶?|
| 2 | 闈舵満娓楅€忔祴璇?(B1-B3) | 楠岃瘉 | 馃敶 P0 | 5澶?|
| 3 | 鍚庢笚閫忔ā鍧?(sudo -l/SUID/鍑嵁/hashdump) | 寮€鍙?| 馃敶 P0 | 5澶?|
| 4 | 淇骞跺彂瀹夊叏闂 (H4/H5) | 淇 | 馃煚 P1 | 2澶?|
| 5 | Payload 鑷€傚簲 (H6: OS/鏋舵瀯鎰熺煡) | 寮€鍙?| 馃煚 P1 | 1澶?|
| 6 | WAF 鑷€傚簲闄嶉€?(H7) | 寮€鍙?| 馃煚 P1 | 1澶?|
| 7 | HTML/PDF 鎶ュ憡 | 寮€鍙?| 馃煛 P2 | 2澶?|
| 8 | 瀹瑰櫒闅旂 (Docker sandbox) | 寮€鍙?| 馃煛 P2 | 2澶?|
| 9 | 鍩哄噯娴嬭瘯濂椾欢 (10-20 闈舵満) | 楠岃瘉 | 馃煛 P2 | 3澶?|
| 10 | 绂荤嚎闄嶇骇绛栫暐 (H9/H10) | 淇 | 馃煝 P3 | 1澶?|

---

## 涓冦€佺湡瀹炴笚閫忚兘鍔涢娴?
鍩轰簬褰撳墠浠ｇ爜璐ㄩ噺鍜屾湭楠岃瘉缁勪欢鐨勯闄╋紝瀵逛笁绫荤洰鏍囩殑棰勬祴锛?
| 鐩爣绫诲瀷 | 棰勮瀹屾垚搴?| 缃俊搴?|
|---------|----------|--------|
| CTF 绠€鍗曢澏鏈?(DVWA/VulnHub Easy) | 60-70% 鑷姩鍖?| 涓?|
| CTF 涓瓑绾у埆 (HTB Easy-Medium) | 30-40% 鑷姩鍖?| 浣?|
| 鐪熷疄浼佷笟娓楅€忔祴璇?| 15-20% (淇℃伅鏀堕泦+婕忔礊鍒嗘瀽) | 浣?|

**鏍稿績鐡堕**: 鍒╃敤寮曟搸鏈粡楠岃瘉鏄涓€鐡堕銆備竴鏃?A1-A3 楠岃瘉閫氳繃骞堕€氳繃 B1-B3 闈舵満娴嬭瘯锛岄璁℃笚閫忓畬鎴愬害鍙彁鍗囧埌 CTF 绠€鍗曠骇鍒?80%+銆佷腑绛?50%+銆?
