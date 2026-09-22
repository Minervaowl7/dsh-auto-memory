// Execute the real host methods with in-memory IO; never open the user's DSH home.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

const source = readFileSync(new URL('../../lib/index.js', import.meta.url), 'utf8')
const host = {}
for (const name of ['parseCalendar', 'renderCalendar', 'calendarAdd']) {
  // Match a complete two-space-indented class method, not a reimplementation.
  const match = source.match(new RegExp('^  (?:async )?' + name + '\\([^\\n]*\\) \\{[\\s\\S]*?^  \\}', 'm'))
  assert.ok(match, 'host method is present: ' + name)
  Object.assign(host, Function('return ({' + match[0] + '})')())
}

test('host calendar reader accepts the untimed format its writer emits', () => {
  const entry = { date: '2026-09-22', time: '--:--', done: true, quadrant: '重要不紧急', title: '保留任务', note: '保留备注' }
  const text = host.renderCalendar([entry])
  assert.deepEqual(host.parseCalendar(text), [entry])
  const timed = { ...entry, time: '9:30', done: false }
  assert.deepEqual(host.parseCalendar(host.renderCalendar([timed])), [timed])
})

test('calendarAdd retains existing untimed items when saving another entry', async () => {
  const entry = { date: '2026-09-22', time: '--:--', done: true, quadrant: '重要不紧急', title: '原有任务', note: '本机备注' }
  let stored = host.renderCalendar([entry])
  const writes = []
  const engine = {
    ...host, state: { calendarText: stored },
    resolvePaths: async () => ({ calendarPath: 'CALENDAR.md' }),
    readTextSafe: async () => stored,
    writeFullRaw: async (file, text) => { writes.push(file); stored = text },
  }
  await engine.calendarAdd({ date: '2026-09-23', time: '09:00', title: '新增事项' })
  let rows = host.parseCalendar(stored)
  assert.equal(rows.length, 2)
  assert.deepEqual(rows[0], entry)
  assert.equal(rows[1].title, '新增事项')
  // Omitted time takes calendarAdd's real default; the next save must retain it too.
  await engine.calendarAdd({ date: '2026-09-24', title: '另一个无时间事项' })
  await engine.calendarAdd({ date: '2026-09-25', time: '10:00', title: '下一次保存' })
  rows = host.parseCalendar(stored)
  assert.equal(rows.length, 4)
  assert.equal(rows[2].time, '--:--')
  assert.deepEqual(rows[0], entry)
  assert.equal(engine.state.calendarText, stored)
  assert.deepEqual(writes, ['CALENDAR.md', 'CALENDAR.md', 'CALENDAR.md'])
})
