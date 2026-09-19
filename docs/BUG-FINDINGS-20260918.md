# BUG-FINDINGS-20260918 — 安全审计 + Bug 猎捕完整清单（供独立复核）

- 基线：`main @ a972ebf`（2026-09-14），扫描执行日 2026-09-18
- 方法：Semgrep 1.177.0（`p/default` 496 规则 + `p/nodejs`/`p/python`/`p/secrets` 226 规则，共 70 文件）→ 人工复核全部命中并补盲（Semgrep 在 `lib/index.js:6220` 与 `.github/scripts/group-digest.mjs:163` 因正则语法报错跳过后文，已人工通读）→ 71 个 smoke 测试 + 1 个 Python 测试全量实跑 → 3 个独立审查代理分别通读 5+4+6 个模块（桥接宿主 / stores / 检索语义），主 agent 对高置信结论逐条源码复验
- 与上轮 `.bug-hunter/`（2026-09-18 同目录，scan-only 11 文件）的关系：其 4 个确认 bug 在 HEAD 全部复验仍成立，编入 §B；BUG-3 驳回结论维持，本文 VT-4 是其**不同**触发序列，请重点审查区分是否成立

## 验证状态图例

- ✅**已验** = 本报告作者逐行读过源码并确认机制链（未运行复现脚本）
- 🧪**代理实测** = 审查代理用注入桩/合成数据实跑复现，作者未重跑
- ⚠️**未重验** = 作者未读源码确认，仅代理断言，置信度采用代理自评
- 所有条目均已人工确认「非 Semgrep 误报」或直接来自人工补盲

---

# §A 安全发现（用户裁定：只记录，不修复）

| ID | 级别 | 位置 | 摘要 | 状态 |
|----|------|------|------|------|
| SE-1 | HIGH | `.github/cloud/qq-webhook/index.js:349` | Ed25519 验签 fail-open：`STRICT_VERIFY=1` 之外验签失败照常处理事件（默认关） | ✅ |
| SE-2 | MED | `qq-webhook/index.js:344` | `op===13` 完全跳过验签（官方协议该事件亦带签名） | ✅ |
| SE-3 | MED | `qq-webhook/index.js:226,262` | `TIMER_SECRET` 未配置（默认空）时 `GET ?timer=1` 零鉴权触发 `workflow_dispatch`；唯一门槛 `ROUTE_TOKEN` 默认亦空 | ✅ |
| SE-4 | MED | `qq-webhook/index.js:270` | `?report=N` 在 `ROUTE_TOKEN` 为空时无鉴权回传 gist 中群成员反馈原文（PII） | ✅ |
| SE-5 | LOW | `qq-webhook/index.js:54` | `RAW_DEBUG` 默认 `'1'`，全部 POST 原始报文写入 gist | ✅ |
| SE-6 | LOW | `group-digest.yml:39-40`、`group-report-status.yml:27-28` | Actions 用可变标签 `@v4` 而非 pin SHA（均第一方 action） | ✅ |
| SE-7 | LOW | `lib/index.js:8082-8092` | `API.update`（loopback-only）执行 `npm install @latest`，`isLoopbackRequest:5716` 对 Origin 缺失放行 → 本机任意进程可静默触发供应链更新；命令本身固定无注入 | ✅ |
| — | 误报 | `insecure-object-assign`×4（index.js:3090/3094/4486、python-setup.js:114）；`unsafe-formatstring`×3 | 合并对象为本地缓存/配置，非 Web 请求体；console.log 无格式化写入面 | ✅排除 |

复核要点：SE-1~4 的攻击面取决于函数实际部署形态（SCF Web 函数公网 URL）；请核实现网 `STRICT_VERIFY`/`ROUTE_TOKEN`/`TIMER_SECRET` 是否已配置——若已配置则降级。

# §B 存量 bug（上轮 `.bug-hunter` 确认，HEAD 复验仍在，未修）

| ID | 位置 | 摘要 | 状态 |
|----|------|------|------|
| OLD-1 | `lib/storage-manage.js:119-120` | `readSidecarPrev` 引用未定义 `docStore`（闭包里只有 `docStoreOf`；:135/:169 的同名是别的函数局部）→ ReferenceError 被 :127 `catch(_){return null}` 吞 → 恒 null → `repair()` 永远 `rebuildSidecar(file, undefined)`，epoch/version 继承静默死亡，每次修复污染证据新鲜度 | ✅（本轮重验） |
| OLD-2 | `lib/evidence-store.js:119` | `_appended.add(id)` 先于链式落盘；`appendFileSync` 一次瞬态失败（Windows AV 锁/EBUSY）→ id 永久驻留缓存 → 进程内同 evidenceId 重试恒被拒 `duplicate-evidence`，事件丢失 | ✅ |
| OLD-3 | `lib/episodic-store.js:291` | `restore` 校验 episodes 但 `current = data.current || null` 零形状校验 → 坏形 `current` 使后续每次 `consolidate()` 在 `current.segments.length` 抛 TypeError，链停摆至重启 | ✅ |
| OLD-4 | `lib/activation-host.js`（导出面）+ `lib/index.js:785-800,834` | `createActivationHost` 的 `disposeRuntime/disposeSession` 全仓零调用（codegraph blast-radius 亦无非 shadow 调用方）→ runtimeState/stepsByRuntime/pathsByKey 每会话泄漏；次级缺陷：activation-host.js:429 按 `String(runtimeKey)` 删 `stepsByRuntime`，而 :275 写入键是 `sessionId+'|ws:'+ws` → 即使接线也是 no-op | ✅ |

# §C 新发现：A 级（数据丢失 / 永久卡死，6 项）

### CA-1 🧪✅ episodic 存储被逐行候选整体覆写 → 永久丢失
`lib/memory-hub.js:98` 对每行 `episodic_candidate` 调 `stores.episodic.restore({schemaVersion:1,episodes:[row]})`，而 `lib/episodic-store.js:282-293` 的 restore 语义是**整体替换**（先 `episodes=[]`）。候选行缺 `episodeId/sessionRef/startedAt/outcome/provenance` → `validateEpisodePre`（:62-76）必拒 → `restored:0` 但返回 `{ok:true}` → hub 记 `consumedEpisodic++`/`outcome:'restored'`。净效果：一次 ingest 抹掉全部已巩固 episode 与 `current`；下次 `consolidate()→persist()` 把清空后的状态落盘。生产可达：`python/worker_semantic_v1.py:749` 对 `len(t)>=80` 的常规行即发此帧，`lib/index.js:6633` 逐行喂。
（附带：上轮 OLD-3 是同文件另一洞。）

### CA-2 ✅ 页预算=传输上限零余量 → Python 后端永久死锁（两代理独立发现）
`lib/index-sync.js:19` `maxPageBytes: 256*1024` 与 `lib/m7-wire.js:25` `maxLineBytes: 256*1024` 同值；`pagePayloadBytes`（index-sync.js:22-24）只算 payload 且以 `pageCount:0` 占位低估，真实帧=envelope(requestId/workerEpoch/sentAt…)+payload+`\n`。payload 落入约 220B 窗口的页必超行限 → `python/worker_v1.py:583-588` 判 oversized、以 `requestId:''` 回错误帧后 `break` 退出 → JS `lib/python-sidecar-client.js:182` 查不到 pending 记 `unknownRequest` 丢弃终局答复 → exit → `rejectAll('crashed')`。死锁核心：`settle`（:196）**任何成功帧把 `consecutiveFailures` 清零**，而每段先 `index_sync_begin` 成功再撞坏页 → 计数最高 2（阈值 3）→ 熔断永不闭合；`syncId` 由 recordCount 确定性派生（m7-wire.js:231）→ 重试恒重建同一坏页 → 每 Segment 重生 worker、重载 BGE-M3、索引永不 ready、`context-host.js:324-352` 门死 `context_push`。桥接代理合成扫描 300 页命中 6 页超限；stores 代理构造出 builder 接受、实测线长 262389>262144 的页（pageCount=37）。

### CA-3 ✅ BOM 坐标系错位 → 单记忆文件永久损坏并从召回消失
`lib/memory-anchor.js:88-89` `parseAnchors` 剥 BOM 后给出全部偏移；`lib/memory-writer.js` 至少五处（:82 `buf[op.atByte-1]!==0x0a` 行首检查、:85 `insertMarkers(buf,…)`、:152、:160、:287 附近）把偏移直接用于**含 BOM** 的原 buffer，索引差 3。三后果：①带 BOM 的 legacy 文件 `planMigration→applyMigrationPlan` 恒 `not-line-start`，锚化迁移死路；②`atByte=0` 时 :82 因 `op.atByte>0` 短路跳过检查 → marker 插到 BOM 之前，BOM 被挤进正文首行，而 `_commit:287` BOM 闸门只看输出前 3 字节 → 放行落盘；③`renderReplace` 无 atByte 行首校验 → marker 落在字符中间（代理实测产出 `li<!-- memory:… -->ne`）→ 重解析 `conflict:orphan-content`。损坏文件此后 append/replace 恒 conflict、`buildSidecar` 恒失败（偏移与原始字节差 3 → `m4-corpus.js:101` 全判 record-stale）→ 该文件在语料/召回中静默消失。旁证：`lib/storage-manage.js:190-192` 显式做 `bomLen` 对齐，唯 memory-writer 漏。Windows 记事本生态 BOM 真实存在。

### CA-4 ✅ append 缺保留语法守卫 → 一次坏内容毒死整个文件的写路径
`lib/memory-writer.js:95-112` `appendAnchoredRecord` 只查本次 `memoryId` 未占用，**不查 `text` 内嵌 marker**；对照同文件 :187-191 `replaceSingleRecord` 专门对 candidate 复解析拒冲突——守卫不对称。正文含文件中已有 ID 的 `<!-- memory:… -->`（文本源自模型/用户沉淀）→ 写入前文件 clean 放行 → 落盘即 duplicate+orphan → 此后该文件每次 append 恒 `conflict:…`、`index.js:3917 appendText` 恒抛。`_commit` 仅查 BOM+digest（复读自洽），类注释宣称的「anchor 唯一校验」未实现。

### CA-5 ✅ 下载器断流追加污染：校验通过但文件是拼接垃圾
`lib/semantic-js.js:430-432` `appendChunk` 用 `flag:'a'`，注释称「首块前由调用方确保不存在」但 `fetchToFile`（:393 起）从不预删 `tmp/<basename>`，双源 mirror 重试直接续追半截残留；sha256 只对**网络流** `hash.update(value)`（:412）累积、不对文件计算 → 完整第二源通过后校验照样通过，`rename` 进 `~/.dsh/models` 的是「半截源A+完整源B」拼接体。代理实测：声明 1000B、400B 断流 → 落位 1400B、`phase:'done'`。118MB onnx 加载期才失败；同洞吞掉磁盘满/截断类错误。

### CA-6 ✅ 事实冲突双方全丢 + 活引用污染展示
`lib/fact-store.js:186-188` `conflicts.push({left: existing})` 持 store 内**活引用**：后续对左事实的 merge 原地改写（代理实测 `confirmedAt` 5000→5100），已展示/已落盘的冲突左侧≠检测时值。:324-328 `resolveConflict(id,'left')` 只置 `resolved=true`，不校验左是否已被 `revokeBySource` 撤销（用户删记忆即级联触发）→ 终态 `query()=[]`、pending 清零、返回 `ok:true`：用户选「保留旧答案」，知识被双向抹除。

# §D 新发现：B 级（行为漂移 / 静默错误，10 项）

| ID | 位置 | 摘要 | 状态 |
|----|------|------|------|
| CB-1 | `lib/semantic-decide.js:33-40` | `normalizeText` 把分隔符**替换为空格**，Python 参照 `m7_activation_features_v2.py:78` 是**整删**（`isalnum`/CJK 之外全滤无空格）→ 连字符/标点处 JS 多切一刀、gram 集与训练词表分叉；`WS_RUN→' '` 先于剥离执行留多空格 bigram 稀释分母；全角数字/é JS 剔 Python 留。代理实测同工件两端 intent 0.3302(suppress) vs 0.5981(emit)、0.8152 vs 0.3429——判定车道翻转 | 🧪✅ |
| CB-2 | `lib/memory-index.js:58,61` ↔ `lib/index.js:962` | `buildIndex` 读 `prev.version`，生产缓存写 `{fileDigest, sourceVersion}` → `prev.version` 恒 undefined → 版本在 1↔2 振荡、非单调可回退，违反 `index.js:938`「进程内递增」承诺。烟测 `smoke-test-memory-index-pre.mjs:20` 恰好传 `version` 键 → 测试全绿掩盖 | ✅ |
| CB-3 | `lib/m7-index-sync-host.js:78,82,120` | `currentEpoch()` 在 `sendIndexSyncPlanPre`（:117 才 lazy spawn）前采样 → 冷启动缓存 `{epoch:null}`：①真 epoch 出现必失配 → 每 worker 生命周期白烧一次全量重同步（分钟级）；②:82 `epoch &&` 前置使 `null` 缓存在进程未运行时永不失效 → 对刚 spawn 的空索引 worker 判 ready=true → 该段 context_push 零候选零激活，诊断误报 `epoch-reset` | ✅ |
| CB-4 | `lib/activation-inbox-state.js:48-52` + `lib/activation-host.js:295,306-312,320-345` | `dropPending` 不清 `claimedPacketId`；pre-step `setCursor` cv 前进丢弃 claimed 态 pending，但 `onPreStep` 刻意不清 `st.claimed`（:306-312 注释自述），`renderTailFor` 照渲、`markDelivered(:155)` 因 claimedPacketId 未清而放行 → 已判 stale 的包写进 messages、计 delivered、起 cooldown、**生成 seen 证据污染后续检索排序**。触发：`pumpClaimed` 挂包后用户再发一段。**与上轮驳回的 BUG-3 不同**：那条是 offer 替换竞态，本条是 stale-drop 后投递，请复核区分 | ✅ |
| CB-5 | `lib/semantic-decide.js:202-205` | `proactive_margin_fallback` 在 explicit 分支内要求 `intent<0.35` 而该分支前提 `intent>=tauLane(0.45)` → 恒假死分支，注释宣称的「无 hit 按 proactive 处理」从未生效；另 :203/:211 `(policy.echoVeto||{}).denseTopArm` 缺 `|| 0`（对照 :140 有），工件缺键时一臂恒假一臂恒真，失败模式相反 | ✅ |
| CB-6 | `lib/temporal-parse.js:64-66` | `nowShiftMonths` 用 `new Date(y,m+n,d…)` 靠 Date 月末进位（注释自述"确定性"但语义错）：now=2026-03-31「最近一个月」起点=03-03（应≈02-29），窗口缩水 2-3 天，29/30/31 日周期性复发；「N个月前」走 `monthStartShift`(day=1) 无此病 → 两臂语义不一致 | ✅🧪 |
| CB-7 | `lib/fact-store.js:149-153` | factId=纯四元组哈希不含撤销态 → `revokeBySource` 后新来源重建同名事实得同 ID 孪生；生产 `index.js:6574/6655/6669` 用持久化 `flushed[factId]` 幂等 → 旧孪生标记置位后新事实被 `continue` 永久静默跳过，不再写回 Markdown | ✅🧪 |
| CB-8 | `lib/activation-inbox.js:86-89` ↔ `lib/context-host.js:480,490` | excerpt 校验按**字节**（`Buffer.byteLength>480`），JS 档生产者按**字符** `.slice(0,ex)`（custom 档 `jsDecideExcerptChars` 上限 480、UI 可调 20-480）→ 中文 >160 字符即整单 `invalid-request:excerpt-budget`、`injectedRejected++` 门口吞掉。默认 40 字符安全；对照 `worker_v1.py:628-630` 先裁再验 utf-8 字节——字节才是契约 | ✅（触发面比代理断言窄） |
| CB-9 | `lib/semantic-js.js:224-226,270,345,441-466` | `degraded` 单向闩锁仅 `_resetForTest` 可清（lib 内零调用）；`probeJsSemanticAssets`/`resolveSemanticTier` 不看 degraded → 引导卡「✓就绪」而 `rank()` 每次抛缓存旧错。下载逐文件落位窗口内一次检索即可永久降级本进程 C2，词法静默兜底；与 `addPeerDirCandidates`「无需重启立即生效」自述矛盾 | ⚠️代理 75 |
| CB-10 | `lib/m7-index-sync-host.js` + `lib/semantic-js.js` | `enabledKeys` 全仓无 `.add` 调用 → `capturedPathKeys` 恒 `[]`；六处 `drop(…,0,…)` → `lastDrop.contextVersion` 恒 0。CA-2/CB-3 类死锁在 `/state` 面板（index.js:4552）不可见、无法归因 | ✅ |

## ⚠️未重验（代理有实测记录、作者未读码，交由复核 agent 定级）

| ID | 位置 | 摘要 | 代理置信 |
|----|------|------|----------|
| CC-1 | `lib/l0-extract.js:138-140` | `growToMin` 先把 `\s+` 压成空格，再用含 `\n` 的 `SENTENCE_SPLIT_RE` 切 → 换行边界分支恒不命中；代理实测日志三条目并成一条膨胀 L0，嵌入向量与 miv 双双劣化 | 72 🧪 |
| CC-2 | `lib/recall-fusion.js:54-56,67-69,88-96` | `ranks.set(memoryId,i+1)` 对重复 id 后写覆盖 → 最优秩丢失、同对象经 `index.js:4092 byId` 占两个名额；二值 temp 臂按 memoryId 强分序 → UUID 序注入排序（实测 60 条池最大位移 21 位、垫底升 167 位，与「软性提升」注释不符） | 70 🧪 |
| CC-3 | `lib/temporal-parse.js:126,152` | 「几十天前」从「十」起匹配→当精确日期解析；`labelToDateMsPre` 未锚定 → 路径 `report-2025-03-14/MEMORY.md` 抽出伪日期挂时间臂；`2026-13-45` 静默进位成 2027-02-13 | 65 🧪 |
| CC-4 | `lib/semantic-decide.js:173-177` | 硬门 reason 取名顺序与 Python（`piiHigh>wrongScope>stale>ignored>correction>harmful`）不一致 → 决策同但 fv2 归因/跨端对齐评估失真 | 62 🧪 |
| CC-5 | `lib/memory-writer.js:235` ↔ `:259` | `_queue` 键 `path.resolve` 大小写敏感，`sidecarPath` 刻意 `.toLowerCase()` → win32 混用大小写调用方=两条并发 RMW 队列 → 丢写+sidecar 分叉（`m4-corpus` stale-source 整源剔除，需设置页手工 repair） | 60（条件触发） |
| CC-6 | `lib/semantic-js.js:413,442-443,450,464` | 进度 `bytesTotal` 基算错 → 每文件下满显 100% 再倒退（实测 1000/1000→1250/1500）；verifying 态黏滞到后续所有文件；`opts.mirrors` 注入点被 :450 硬编码常量废掉 | 68 🧪 |
| CC-7 | `lib/python-sidecar-client.js:104-107,211-214` + `:108-116` | 三路 stdio 均无 `error` 监听：worker 死亡后写 → 'error' 无监听事件环级抛出（宿主全局 uncaughtException 兜住）→ `done()` 截断、writeChain 后续帧永挂、`writeFrame` 仍返回 true → 客户端假活；`proc.on('error')` 缺 `child===proc` 身份门（:117 exit 有）→ 晚到 ESRCH 摘掉活进程引用但不 kill → Python+模型孤儿常驻、下次再 spawn 堆积 | ✅（监听缺失已读码确认；后果链 66） |
| CC-8 | `lib/python-sidecar-client.js:164` | `epoch!==null` 时 fail-**open**：exit 置 epoch=null 后、stdio 排空前，旧 worker 尾帧照进 `feed`；`activation_request` 完全绕过 epoch 门 → 僵尸 worker 激活照常投递（文件头 :7 承诺 fail closed）；旧进程无 `\n` 尾字节污染新 buffer → 新 worker 首帧 badJson、请求白等超时 | 60 |
| CC-9 | `lib/python-sidecar-client.js:211-214` | 延后写绑定「当时的 child」而非建帧时 child：中途 respawn → 旧 epoch 帧进新 worker → epoch-mismatch 回帧被判 staleEpoch 丢弃 → 有终局答复仍挂满 120s | 55 |
| CC-10 | `lib/activation-inbox.js:347-355` ↔ `lib/activation-host.js:329` | packet 构建用 `req.threshold.reason`（sanitize 后）渲染、`triggerReason` 存未 sanitize 原文，重渲染改用后者 → 凡 reason 含换行/连续空格/尾空格/`<!--` 即 digest-mismatch 整单零注入。当前生产者 reason 模板恰好干净 → **潜伏态**；fv2 空 reasonCodes 会留尾空格值得实测 | 58 |
| CC-11 | `lib/activation-host.js:273-279,210,161` | `stepFor` 是自增器却被 getter 式双调用（offer+pump 各 +1）→ expiresAtStep 按第一次烘焙、判定用第二次起 → 默认 ttlSteps=3 实际窗口 1-2 步，投递窗比 §8 文档窄半 | 45 |
| CC-12 | `lib/memory-hub.js:80-82` ↔ `lib/fact-store.js:396-401,412` | `stores.facts.factCandidateFromJudgementRow` 恒 undefined（方法是模块级导出、store 对象上没有）→ 委托分支死码，永远走 hub :224 本地已漂移副本（丢 `ttl`）；当前 worker 不产 ttl 无实害，两处适配器从此各自演化 | ✅（机制已读码确认） |
| CC-13 | 零散 | `python-sidecar-client.js` `restart()` 违背注释（生产不可达，仅 m70 测试调用）；`memory-writer.js:312,322` `dirty` 标志全仓无读者；`fact-store.js:387-388` `clear()` 漏重置 revoked/conflictAdded、`supersede()` 返回值错位且 `stats.superseded` 死路径 | 55-60 |

# §E 测试套件腐坏（12 项红，零 CI）

无 test CI：`.github/workflows` 只有 group-digest/group-report-status 两条，均不跑测试 → 红测试静默积累。运行方式：`for f in tests/smoke/*.mjs; do node $f; done`（60/71 过）+ `python tests/test_m7_features_v2.py`。

**「去-pre 发布转换」(fbc14fb) 漏改，同 5df0907 已修一类（断言/资产指向 v2.2.4 前旧名）：**
1. `smoke-test-m53-pre.mjs:290` C8：断言组件名含 `-pre`
2. `smoke-test-m63-pre.mjs:192` F7：同上
3. `smoke-test-p4-l0-response-pre.mjs:40`：守卫 `memory-anchor-pre.js` 导入（实际 `memory-anchor.js`）
4. `smoke-test-p9d-recent-evidence-ts-pre.mjs:89`：断言「`lib/context-host.js` 不得含修复代码」——修复已合入，断言方向反转
5. `smoke-test-m72-pre.mjs:28` + `tests/m7-2-fixtures/embedding-fixture.json:15`：fixture 冻结值仍是 `m7_chunk_pre_v1`，运行时（`python/m7_embedding_v1.py:31`）为 `m7_chunk_v1`
6. `tests/test_m7_features_v2.py:23,29-30`：import `m7_activation_features_pre_v2`（实为 `_v2`）、策略 `recall_intent_lr_pre_v1.json`（实为无 pre）、夹具目录 `artifacts/m7-live-pre/` 不存在——自 fbc14fb 一次都跑不起来

**不隔离环境 / 缺前置且无 skip 守卫（在作者机上可能同样红或依赖私有数据）：**
7. `smoke-test-peer-probe-pre.mjs:50,96`：未设 `DSH_HOME` → 本机真实 `~/.dsh/models/js-semantic`（存在）命中 `semantic-js.js:168` home 优先候选（产品行为系设计，注释 :71 明示），遮蔽临时夹具 → 假阳性
8. `smoke-test-m81-c2-wiring-pre.mjs:56`：同上根因（`assetPresent` 恒 true）
9. `smoke-test-m79-feature-v2-pre.mjs:12,24` + `smoke-test-m710-fv2-emit-pre.mjs:15`：硬编码 `python/bench/.venv/Scripts/python.exe`，仓库无 `python/bench` 且无文档 → spawn 失败 stderr 为空、错误不可归因
10. `smoke-test-m81-fact-metadata-pre.mjs`：要求开发者本机真实 `facts.json`
11. `smoke-test-c4-fresh-install-pre.mjs:32`：依赖未入库的 `artifacts/release-c2-asset-pack/*.tgz` → `execFileSync` 裸崩而非 skip

# §F 横切模式（给复核 agent 的找同类线索）

1. **双实现 parity 靠注释**：JS↔Python 各写一份 normalizeText/门顺序/预算单位（CB-1/5/6、CC-4），无共享黄金向量
2. **同文件守卫不对称**：replace 复解析 vs append 不复解析（CA-4）；exit 有身份门 vs error 没有（CC-7）
3. **测试形状≠生产形状**：CB-2 夹具键名恰好掩盖；§E-7/8 夹具被真实 home 遮蔽
4. **预算边界零余量**：CA-2 的 256KiB==256KiB、CB-8 字节/字符单位错配
5. **未接线静默死亡族**：OLD-1/OLD-4、CB-10、CC-12、User-scope 编排入口 `ensureWorkspaceIndexReady`（m7-index-sync-host.js:149）零调用方、`context-host.js:547` 硬编码 `'Workspace'` → 用户级 MEMORY.md 恒不进 worker 索引
6. **恒假/黏滞状态**：CB-5 死分支、CB-9 单向闩锁、CC-6 黏滞 phase

# §G 请复核 agent 重点裁决

1. **CA-1/CB-4 的完整触发序列实跑**（代理注入桩未覆盖真实 worker 帧形状；`episodic_candidate` 行的实际字段集请以 `worker_semantic_v1.py:749` 上下文为准再核一遍是否真缺必填键）
2. **CA-2 窗口宽度**：+232B 信封开销是两个代理的估算/实测混合，请按真实 envelope 字段宽度重算临界窗口与超限概率
3. **CB-1 数值**：两端 intent 差异是代理用同一工件实跑的，但归一化差异的净影响依赖词表命中分布，建议独立重跑
4. **§C/§D 之外全部 ⚠️ 条目**：先读码定性再谈级别
5. 本文所有「生产可达」断言基于 `lib/index.js` 装配路径抽查，未逐 route 复核
6. 修复优先级建议：CA-1/CA-3/CA-4/CA-6（不可逆数据损坏）→ CA-2/CA-5（永久卡死）→ §D（漂移）→ §E（先补 test CI 再修红，防回归）→ §C（按用户指示不修，仅记录）

— 由 Qoder 会话（Semgrep + 3 并行审查代理 + 主 agent 复验）生成；行号以 `main@a972ebf` 为准。
