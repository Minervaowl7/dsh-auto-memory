// Regression tests for v3.1.3 migration data preservation.
// Real exported functions only; no host, network, home-directory or disk writes.
import assert from 'node:assert/strict'
import test from 'node:test'
import {
  buildPackPre, validatePackPre, rewritePathsInTextPre,
  rewritePackForTargetPre, workspaceSlugPre, planImportPre,
  renameForConflictPre, calendarMergePre, mergeSummaryRecordPre,
} from '../../lib/migrate-pack.js'

const rewrite = (text, fromPath, toPath) => rewritePathsInTextPre(text, { fromPath, toPath })
const makePack = (files, ws = '/project') => {
  const result = buildPackPre({ ws, files, now: 1 })
  assert.equal(result.ok, true)
  assert.equal(validatePackPre(result.pack).ok, true)
  return result.pack
}

test('Windows path representations stay paired even when JSON becomes longer than the URI', () => {
  const shallow = String.raw`D:\proj`
  const deep = String.raw`C:\a\b\c\d\e\f\g\h\i`
  for (const [fromPath, toPath] of [[shallow, deep], [deep, shallow]]) {
    const fromSlash = fromPath.replaceAll('\\', '/')
    const toSlash = toPath.replaceAll('\\', '/')
    const cases = [
      [fromPath, toPath],
      [fromSlash, toSlash],
      ['file:///' + fromSlash, 'file:///' + toSlash],
      [JSON.stringify({ path: fromPath }), JSON.stringify({ path: toPath })],
    ]
    for (const [input, expected] of cases) {
      assert.deepEqual(rewrite(input, fromPath, toPath), { text: expected, hits: 1 })
    }
  }
})

test('replacement output is not processed again when target contains source', () => {
  const from = String.raw`D:\proj`
  const to = String.raw`D:\proj\copy`
  const input = String.raw`D:\proj | D:/proj | file:///D:/proj | D:\\proj`
  const expected = String.raw`D:\proj\copy | D:/proj/copy | file:///D:/proj/copy | D:\\proj\\copy`
  assert.deepEqual(rewrite(input, from, to), { text: expected, hits: 4 })
  assert.deepEqual(rewrite('file:///old/project/note.md', '/old/project', '/old/project/copy'), {
    text: 'file:///old/project/copy/note.md', hits: 1,
  })
})

test('Windows to POSIX keeps valid JSON and a canonical file URI', () => {
  const from = String.raw`D:\proj`
  const to = '/home/user/proj'
  const r = rewrite(JSON.stringify({ path: from }), from, to)
  assert.deepEqual(JSON.parse(r.text), { path: to })
  assert.deepEqual(rewrite('file:///D:/proj/readme.md', from, to), {
    text: 'file:///home/user/proj/readme.md', hits: 1,
  })
})

test('POSIX to Windows uses JSON-safe forward slashes for ambiguous unescaped paths', () => {
  const from = '/old/project'
  const to = String.raw`C:\work\project`
  assert.deepEqual(rewrite('see /old/project/note.md', from, to), {
    text: 'see C:/work/project/note.md', hits: 1,
  })
  assert.deepEqual(JSON.parse(rewrite(JSON.stringify({ path: from }), from, to).text), {
    path: 'C:/work/project',
  })
  for (const prefix of ['file://', 'file:///']) {
    assert.deepEqual(rewrite(prefix + from + '/note.md', from, to), {
      text: 'file:///C:/work/project/note.md', hits: 1,
    })
  }
})

test('path metacharacters and replacement dollar signs are literal', () => {
  const from = '/old/a.[x](y)+$^'
  const to = '/new/$&/a.[x](y)+$^'
  assert.deepEqual(rewrite('see ' + from + '/a.md', from, to), {
    text: 'see ' + to + '/a.md', hits: 1,
  })
  assert.deepEqual(rewrite('unrelated /old/anything', from, to), {
    text: 'unrelated /old/anything', hits: 0,
  })
})

test('same paths, disabled rewriting, empty input and slug-only rewrites retain their contracts', () => {
  const ws = String.raw`D:\proj`
  const raw = String.raw`file:///D:/proj D:\\proj --D--proj--`
  assert.deepEqual(rewrite(raw, ws, ws), { text: raw, hits: 0 })
  assert.deepEqual(rewritePathsInTextPre(null), { text: '', hits: 0 })
  assert.deepEqual(rewritePathsInTextPre('old old', { fromSlug: 'old', toSlug: 'old-new' }), {
    text: 'old-new old-new', hits: 2,
  })
  const pack = makePack({ 'MEMORY.md': raw }, ws)
  const same = rewritePackForTargetPre(pack, { targetWs: ws })
  assert.equal(same.files['MEMORY.md'], raw)
  assert.equal(same.plan.totalHits, 0)
  const disabled = rewritePackForTargetPre(pack, { targetWs: 'C:\\work', rewriteBody: false })
  assert.equal(disabled.files['MEMORY.md'], raw)
  assert.equal(disabled.plan.totalHits, 0)
  assert.equal(workspaceSlugPre(ws), '--D--proj--')
})

test('pack rewriting reports exact changed files and preserves unrelated content', () => {
  const from = String.raw`D:\proj`
  const to = String.raw`D:\proj\copy`
  const pack = makePack({
    'handoff/index.json': JSON.stringify({ path: from, url: 'file:///D:/proj' }),
    'MEMORY.md': 'unrelated',
  }, from)
  const result = rewritePackForTargetPre(pack, { targetWs: to })
  assert.deepEqual(JSON.parse(result.files['handoff/index.json']), { path: to, url: 'file:///D:/proj/copy' })
  assert.equal(result.files['MEMORY.md'], 'unrelated')
  assert.equal(result.plan.totalHits, 2)
  assert.deepEqual(result.plan.rewriteFiles, [{ path: 'handoff/index.json', hits: 2 }])
  assert.equal(validatePackPre(pack).ok, true, 'source pack is not mutated')
})

test('rename never overwrites an existing from-pack backup or occupied numbered name', () => {
  const pack = makePack({ 'MEMORY.md': 'incoming' })
  const existing = {
    'MEMORY.md': 'local',
    'MEMORY.from-pack.md': 'previous import',
    'MEMORY.from-pack-2.md': 'another import',
  }
  const before = JSON.stringify(existing)
  const plan = planImportPre(pack, { targetWs: '/project', existingFiles: existing, onConflict: 'rename' })
  assert.deepEqual(plan.writeFiles, { 'MEMORY.from-pack-3.md': 'incoming' })
  assert.deepEqual(plan.overwrites, [])
  assert.equal(plan.additions[0].renamedFrom, 'MEMORY.md')
  assert.equal(plan.stats.willWrite, 1)
  assert.equal(JSON.stringify(existing), before)
})

test('rename reserves incoming names before iteration, independent of input order', () => {
  for (const reverse of [false, true]) {
    const entries = [['MEMORY.md', 'incoming'], ['MEMORY.from-pack.md', 'incoming backup']]
    const pack = makePack(Object.fromEntries(reverse ? entries.reverse() : entries))
    const plan = planImportPre(pack, {
      targetWs: '/project', existingFiles: { 'MEMORY.md': 'local' }, onConflict: 'rename',
    })
    assert.deepEqual(plan.writeFiles, { 'MEMORY.from-pack-2.md': 'incoming', 'MEMORY.from-pack.md': 'incoming backup' })
    assert.equal(plan.stats.willWrite, 2)
    assert.equal(new Set(plan.additions.map((a) => a.path)).size, 2)
  }
})

test('rename collision probing preserves extensions and extensionless names', () => {
  for (const name of ['handoff/PLAN.md', 'MEMORY', 'dir.with.dot/MEMORY']) {
    const first = renameForConflictPre(name)
    const plan = planImportPre(makePack({ [name]: 'incoming' }), {
      targetWs: '/project', existingFiles: { [name]: 'local', [first]: 'backup' }, onConflict: 'rename',
    })
    assert.equal(Object.keys(plan.writeFiles).length, 1)
    assert.equal(plan.writeFiles[name], undefined)
    assert.equal(plan.writeFiles[first], undefined)
    assert.equal(Object.values(plan.writeFiles)[0], 'incoming')
  }
  assert.equal(renameForConflictPre('handoff/PLAN.md'), 'handoff/PLAN.from-pack.md')
})

test('keep, overwrite, equal-content and first available rename behavior is unchanged', () => {
  const pack = makePack({ 'MEMORY.md': 'incoming', 'new.md': 'new' })
  const options = { targetWs: '/project', existingFiles: { 'MEMORY.md': 'local' } }
  assert.deepEqual(planImportPre(pack, options).writeFiles, { 'new.md': 'new' })
  assert.equal(planImportPre(pack, { ...options, onConflict: 'overwrite' }).overwrites.length, 1)
  assert.deepEqual(planImportPre(pack, { ...options, onConflict: 'rename' }).writeFiles, {
    'MEMORY.from-pack.md': 'incoming', 'new.md': 'new',
  })
  assert.equal(planImportPre(pack, { ...options, existingFiles: { 'MEMORY.md': 'incoming' } }).overwrites.length, 0)
})

test('calendar merge preserves local undated-time entries alongside incoming timed entries', () => {
  const local = '## 2026-09-22\n- [ ] --:-- | 重要 | 本机任务 | 待安排\n'
  const incoming = '## 2026-09-23\n- [ ] 09:00 | 重要 | 导入任务\n'
  const result = calendarMergePre(local, incoming)
  assert.equal(result.ok, true)
  assert.equal(result.kept, 1)
  assert.equal(result.added, 1)
  assert.ok(result.text.includes('- [ ] --:-- | 重要 | 本机任务 | 待安排'))
  assert.ok(result.text.includes('- [ ] 09:00 | 重要 | 导入任务'))
})

test('calendar imports untimed entries and preserves local completion and note on collision', () => {
  const local = '## 2026-09-22\n- [X] --:-- | 重要 | 相同任务 | 本机备注\n'
  const incoming = '## 2026-09-22\n- [ ] --:-- | 重要 | 相同任务 | 外机备注\n- [ ] --:-- | 普通 | 新任务\n'
  const result = calendarMergePre(local, incoming)
  assert.equal(result.kept, 1)
  assert.equal(result.added, 1)
  assert.ok(result.text.includes('- [x] --:-- | 重要 | 相同任务 | 本机备注'))
  assert.ok(result.text.includes('- [ ] --:-- | 普通 | 新任务'))
  assert.ok(!result.text.includes('外机备注'))
  const again = calendarMergePre(result.text, incoming)
  assert.equal(again.added, 0)
  assert.equal(again.kept, 2)
  assert.equal(again.text, result.text)
})

test('timed calendar duplicates and unrelated workspace summaries remain preserved', () => {
  const text = '## 2026-09-22\n- [x] 09:00 | 重要 | 任务 | 备注\n'
  const merged = calendarMergePre(text, text)
  assert.equal(merged.kept, 1)
  assert.equal(merged.added, 0)
  assert.ok(merged.text.includes('- [x] 09:00 | 重要 | 任务 | 备注'))
  const summary = { workspaces: [{ path: '/other', items: ['keep'] }] }
  const result = mergeSummaryRecordPre(summary, { items: ['incoming'] }, '/project')
  assert.deepEqual(result.summary.workspaces[0], summary.workspaces[0])
  assert.equal(result.summary.workspaces.length, 2)
  assert.equal(summary.workspaces.length, 1)
})
