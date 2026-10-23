/*
Copyright (C) 2023-2026 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please contact support@quantumnous.com
*/
import { spawnSync } from 'node:child_process'
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { delimiter, dirname, join, resolve } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

const script = resolve('scripts/format-with-protected-headers.mjs')
const copyrightMatch = readFileSync(script, 'utf8').match(
  /^\/\*[\s\S]*?\*\/\n+/
)
if (!copyrightMatch) throw new Error('Formatter copyright header is required')
const copyright = copyrightMatch[0]
const formattedBody = 'const value = 1\n'
const temporaryRoots: string[] = []
const formatterStub = String.raw`
const { readFileSync, readdirSync, writeFileSync } = require('node:fs')
const { join } = require('node:path')
if (readFileSync(process.env.ORIGINAL_SOURCE, 'utf8') !== process.env.ORIGINAL_BYTES) process.exit(73)
if (process.env.CONCURRENT_EDIT === '1') writeFileSync(process.env.ORIGINAL_SOURCE, process.env.ORIGINAL_BYTES + '// concurrent edit\n')
function formatDirectory(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name)
    if (entry.isDirectory() && entry.name !== 'node_modules') formatDirectory(path)
    if (entry.isFile() && path.endsWith('.ts')) {
      writeFileSync(path, readFileSync(path, 'utf8').replace(/const value\s*=\s*1;?\n?/, 'const value = 1\n'))
    }
  }
}
formatDirectory(process.cwd())
if (process.env.FORMATTER_FAIL === '1') process.exit(29)
`

function fixture(body = formattedBody) {
  const directory = mkdtempSync(join(tmpdir(), 'newapi-format-contract-'))
  temporaryRoots.push(directory)
  const project = join(directory, 'project')
  const bin = join(directory, 'bin')
  const modules = join(directory, 'shared-modules')
  mkdirSync(join(project, 'src'), { recursive: true })
  mkdirSync(bin)
  mkdirSync(modules)
  writeFileSync(join(modules, 'sentinel'), 'shared dependency remains')
  symlinkSync(modules, join(project, 'node_modules'), 'dir')
  writeFileSync(join(project, '.oxfmtrc.json'), '{\n  "semi": false\n}\n')
  writeFileSync(join(project, '.gitignore'), 'node_modules\n')
  const file = join(project, 'src', 'example.ts')
  writeFileSync(file, copyright + body)
  chmodSync(file, 0o744)
  writeFileSync(join(bin, 'oxfmt'), `#!${process.execPath}\n${formatterStub}`)
  chmodSync(join(bin, 'oxfmt'), 0o755)
  return { directory, project, bin, modules, file }
}

function run(
  f: ReturnType<typeof fixture>,
  mode: '--check' | '--write',
  extra: Record<string, string> = {}
) {
  return spawnSync(process.execPath, [script, mode], {
    cwd: f.project,
    encoding: 'utf8',
    timeout: 15000,
    env: {
      ...process.env,
      PATH: f.bin + delimiter + process.env.PATH,
      ORIGINAL_SOURCE: f.file,
      ORIGINAL_BYTES: readFileSync(f.file, 'utf8'),
      ...extra,
    },
  })
}

afterEach(() => {
  for (const directory of temporaryRoots.splice(0)) {
    rmSync(directory, { recursive: true, force: true })
  }
})

describe('protected-header formatter CLI', () => {
  it('checks formatted inputs without writing them, including while the formatter runs', () => {
    const f = fixture()
    const before = statSync(f.file, { bigint: true })
    const result = run(f, '--check')
    expect(result.error).toBeUndefined()
    expect(result.status, result.stderr).toBe(0)
    expect(readFileSync(f.file, 'utf8')).toBe(copyright + formattedBody)
    expect(statSync(f.file, { bigint: true }).mtimeNs).toBe(before.mtimeNs)
    expect(readFileSync(join(f.modules, 'sentinel'), 'utf8')).toBe(
      'shared dependency remains'
    )
  })

  it('reports an unformatted body without rewriting or restoring the original file', () => {
    const f = fixture('const value=1;\n')
    const before = statSync(f.file, { bigint: true })
    const result = run(f, '--check')
    expect(result.status, result.stderr).toBe(1)
    expect(result.stderr).toContain('src/example.ts')
    expect(readFileSync(f.file, 'utf8')).toBe(`${copyright}const value=1;\n`)
    expect(statSync(f.file, { bigint: true }).mtimeNs).toBe(before.mtimeNs)
  })

  it('writes the formatted body with the exact original header and file permissions', () => {
    const f = fixture('const value=1;\n')
    const result = run(f, '--write')
    expect(result.status, result.stderr).toBe(0)
    expect(readFileSync(f.file, 'utf8')).toBe(copyright + formattedBody)
    expect(statSync(f.file).mode & 0o777).toBe(0o744)
  })

  it('keeps original bytes on a formatter failure after partial scratch output', () => {
    const f = fixture('const value=1;\n')
    const before = statSync(f.file, { bigint: true })
    const result = run(f, '--write', { FORMATTER_FAIL: '1' })
    expect(result.status, result.stderr).toBe(29)
    expect(readFileSync(f.file, 'utf8')).toBe(`${copyright}const value=1;\n`)
    expect(statSync(f.file, { bigint: true }).mtimeNs).toBe(before.mtimeNs)
    expect(readFileSync(join(f.modules, 'sentinel'), 'utf8')).toBe(
      'shared dependency remains'
    )
  })

  it('leaves an unrelated concurrent edit intact instead of restoring its snapshot', () => {
    const f = fixture()
    const result = run(f, '--check', { CONCURRENT_EDIT: '1' })
    expect(result.status, result.stderr).toBe(1)
    expect(readFileSync(f.file, 'utf8')).toBe(
      `${copyright}${formattedBody}// concurrent edit\n`
    )
  })

  it('preserves a later target edited after an earlier target was published', () => {
    const f = fixture('const value=1;\n')
    const laterFile = join(f.project, 'src', 'later.ts')
    const lateBytes = `${copyright}const value=1;\n// late edit\n`
    writeFileSync(laterFile, `${copyright}const value=1;\n`)
    const preload = join(f.directory, 'late-editor.mjs')
    writeFileSync(
      preload,
      String.raw`
import fs from 'node:fs'
import { syncBuiltinESMExports } from 'node:module'
const rename = fs.renameSync
let edited = false
fs.renameSync = function (source, target) {
  rename(source, target)
  if (!edited && target === process.env.ORIGINAL_SOURCE) {
    edited = true
    fs.writeFileSync(process.env.LATE_EDIT_SOURCE, process.env.LATE_EDIT_BYTES)
  }
}
syncBuiltinESMExports()
`
    )
    const result = run(f, '--write', {
      NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ''} --import=${preload}`,
      LATE_EDIT_SOURCE: laterFile,
      LATE_EDIT_BYTES: lateBytes,
    })
    expect(result.status, result.stderr).toBe(1)
    expect(result.stderr).toContain(
      'File changed during formatting: src/later.ts'
    )
    expect(readFileSync(f.file, 'utf8')).toBe(copyright + formattedBody)
    expect(readFileSync(laterFile, 'utf8')).toBe(lateBytes)
  })

  it('preserves real oxfmt configuration and ignored generated files', () => {
    const f = fixture()
    const web = resolve(dirname(script), '..')
    writeFileSync(join(f.project, '.gitignore'), 'node_modules\nignored.ts\n')
    writeFileSync(
      join(f.project, '.oxfmtrc.json'),
      '{\n  "semi": false,\n  "ignorePatterns": ["**/routeTree.gen.ts"]\n}\n'
    )
    writeFileSync(join(f.project, 'ignored.ts'), 'const = invalid')
    writeFileSync(
      join(f.project, 'src', 'routeTree.gen.ts'),
      'const = generated'
    )
    const result = spawnSync(process.execPath, [script, '--check'], {
      cwd: f.project,
      encoding: 'utf8',
      timeout: 15000,
      env: {
        ...process.env,
        PATH: join(web, 'node_modules', '.bin') + delimiter + process.env.PATH,
      },
    })
    expect(result.status, result.stderr).toBe(0)
    expect(readFileSync(f.file, 'utf8')).toBe(copyright + formattedBody)
    expect(readFileSync(join(f.project, 'ignored.ts'), 'utf8')).toBe(
      'const = invalid'
    )
    expect(
      readFileSync(join(f.project, 'src', 'routeTree.gen.ts'), 'utf8')
    ).toBe('const = generated')
  })
})
