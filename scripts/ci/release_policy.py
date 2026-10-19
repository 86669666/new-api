#!/usr/bin/env python3
"""Fail-closed release decisions; no network or publishing side effects."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


IMAGE = 'calciumion/new-api'
STABLE = re.compile(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)')
VERSION = re.compile(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?')


def promotion(tag, tags):
    if not VERSION.fullmatch(tag):
        raise ValueError('expected a vMAJOR.MINOR.PATCH release tag, optionally prerelease')
    match = STABLE.fullmatch(tag)
    if not match:
        return False
    stable = [tuple(map(int, m.groups())) for t in tags if (m := STABLE.fullmatch(t))]
    version = tuple(map(int, match.groups()))
    # No proof that this is the newest known stable tag means no promotion.
    return bool(stable) and version == max(stable) and tag in tags


def preview_alias(branch):
    # Hash the full, case-sensitive name before lossy slugging/truncation.
    digest = hashlib.sha256(branch.encode('utf-8')).hexdigest()[:24]
    slug = re.sub(r'[^a-z0-9_.-]+', '-', branch.lower()).strip('.-')[:32] or 'branch'
    return f'preview-{slug}-{digest}'


def quality_results(results):
    required = {'backend', 'frontend', 'database'}
    if set(results) != required or any(results[name] != 'success' for name in required):
        raise ValueError('every required quality job must succeed; missing/skipped/cancelled is not success')


def digest_sources(records, sha, run_id, attempt):
    if not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise ValueError('candidate must be a full commit SHA')
    if len(records) != 2:
        raise ValueError('exactly two architecture receipts are required')
    found = {}
    for record in records:
        arch = record.get('arch')
        if arch not in ('amd64', 'arm64') or arch in found:
            raise ValueError('missing or duplicate architecture')
        expected = {'sha': sha, 'run_id': str(run_id), 'attempt': str(attempt), 'image': IMAGE}
        if any(record.get(k) != v for k, v in expected.items()):
            raise ValueError('receipt belongs to another candidate, run, attempt, or image')
        digest = record.get('digest', '')
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
            raise ValueError('invalid immutable image digest')
        found[arch] = IMAGE + '@' + digest
    return [found[arch] for arch in ('amd64', 'arm64')]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['promotion', 'receipt', 'sources', 'quality', 'preview-alias'])
    parser.add_argument('--tag')
    parser.add_argument('--branch')
    parser.add_argument('--directory', type=Path)
    args = parser.parse_args()
    if args.command == 'promotion':
        tags = subprocess.check_output(['git', 'tag', '--list'], text=True).splitlines()
        print('true' if promotion(args.tag, tags) else 'false')
    elif args.command == 'preview-alias':
        if not args.branch:
            parser.error('--branch is required')
        print(preview_alias(args.branch))
    elif args.command == 'quality':
        quality_results(json.loads(os.environ['QUALITY_RESULTS']))
    elif args.command == 'receipt':
        record = {key: os.environ[env] for key, env in (
            ('sha', 'CANDIDATE_SHA'), ('run_id', 'GITHUB_RUN_ID'),
            ('attempt', 'GITHUB_RUN_ATTEMPT'), ('arch', 'ARCH'), ('digest', 'DIGEST'))}
        record['image'] = IMAGE
        args.directory.mkdir(parents=True, exist_ok=True)
        (args.directory / (record['arch'] + '.json')).write_text(json.dumps(record) + '\n')
    else:
        records = [json.loads(p.read_text()) for p in args.directory.glob('*.json')]
        print('\n'.join(digest_sources(records, os.environ['CANDIDATE_SHA'],
                                      os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT'])))


if __name__ == '__main__':
    main()
