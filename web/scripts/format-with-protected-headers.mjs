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
import { randomUUID } from 'node:crypto'
import {
  closeSync,
  existsSync,
  fchmodSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join, relative } from 'node:path'

const mode = process.argv[2]

if (mode !== '--check' && mode !== '--write') {
  console.error(
    'Usage: node scripts/format-with-protected-headers.mjs --check|--write'
  )
  process.exit(2)
}

const root = process.cwd()
const excludedDirs = new Set([
  '.git',
  '.tanstack',
  'build',
  'coverage',
  'dist',
  'node_modules',
])
const headerExtensions = new Set([
  '.cjs',
  '.cts',
  '.js',
  '.jsx',
  '.mjs',
  '.mts',
  '.ts',
  '.tsx',
])
const protectedHeaderPattern =
  /^\/\*\nCopyright \(C\)[\s\S]*?QuantumNous[\s\S]*?\*\/\n+/

function extensionOf(path) {
  const index = path.lastIndexOf('.')
  return index === -1 ? '' : path.slice(index)
}

function walk(dir, files = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!excludedDirs.has(entry.name)) {
        walk(join(dir, entry.name), files)
      }
      continue
    }

    if (entry.isFile()) {
      files.push(join(dir, entry.name))
    }
  }

  return files
}

function snapshotFiles(files, scratch) {
  const snapshot = new Map()
  for (const file of files) {
    const content = readFileSync(file)
    const header = headerExtensions.has(extensionOf(file))
      ? (content.toString('utf8').match(protectedHeaderPattern)?.[0] ?? '')
      : ''
    snapshot.set(file, { content, header, mode: statSync(file).mode & 0o777 })
    const target = join(scratch, relative(root, file))
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, content.subarray(Buffer.byteLength(header)))
  }
  return snapshot
}

const files = walk(root).filter(
  (file) => statSync(file).size < 10 * 1024 * 1024
)
const scratch = mkdtempSync(join(tmpdir(), 'new-api-format-'))
let exitCode = 0

try {
  // Only this private scratch contains header-free copies. Original files stay
  // untouched until a successful --write has complete, header-preserving output.
  const before = snapshotFiles(files, scratch)
  const modules = join(root, 'node_modules')
  if (existsSync(modules)) {
    symlinkSync(modules, join(scratch, 'node_modules'), 'dir')
  }
  const result = spawnSync(
    'oxfmt',
    ['-c', '.oxfmtrc.json', '--ignore-path', '.gitignore', '--write', '.'],
    { cwd: scratch, stdio: 'inherit' }
  )
  exitCode = result.status ?? 1
  if (result.error) throw result.error

  if (exitCode === 0) {
    const changed = new Map()
    for (const [file, original] of before) {
      const output = readFileSync(join(scratch, relative(root, file)))
      const formatted = original.header
        ? Buffer.from(
            original.header + output.toString('utf8').replace(/^\n+/, '')
          )
        : output
      if (!original.content.equals(formatted)) changed.set(file, formatted)
    }

    // Never restore snapshots over changes made by an editor or another tool.
    for (const [file, original] of before) {
      if (
        !readFileSync(file).equals(original.content) ||
        (statSync(file).mode & 0o777) !== original.mode
      ) {
        throw new Error(
          `File changed during formatting: ${relative(root, file)}`
        )
      }
    }

    if (mode === '--check') {
      if (changed.size > 0) {
        console.error('Format issues found in protected-header-safe check:')
        for (const file of changed.keys()) console.error(relative(root, file))
        exitCode = 1
      }
    } else {
      for (const [file, content] of changed) {
        const original = before.get(file)
        const temporary = join(
          dirname(file),
          `.${basename(file)}.oxfmt-${randomUUID()}`
        )
        // Claim a new file before entering cleanup, so a collision cannot cause
        // removal of a path this process did not create.
        const descriptor = openSync(temporary, 'wx', original.mode)
        try {
          try {
            writeFileSync(descriptor, content)
            fchmodSync(descriptor, original.mode)
          } finally {
            closeSync(descriptor)
          }
          // Recheck this target after preparing its output: earlier batch writes
          // may have given an editor time to change it. --write still requires a
          // single writer; the filesystem offers no portable compare-and-swap.
          if (
            !readFileSync(file).equals(original.content) ||
            (statSync(file).mode & 0o777) !== original.mode
          ) {
            throw new Error(
              `File changed during formatting: ${relative(root, file)}`
            )
          }
          renameSync(temporary, file)
        } finally {
          rmSync(temporary, { force: true })
        }
      }
    }
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error))
  exitCode = 1
} finally {
  // This exact fresh directory is owned by this invocation. rmSync does not
  // follow its node_modules symlink, so the shared dependency directory remains.
  rmSync(scratch, { recursive: true, force: true })
}

process.exit(exitCode)
