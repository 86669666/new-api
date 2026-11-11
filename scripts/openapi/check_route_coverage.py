#!/usr/bin/env python3
"""Static classification/drift check for router/task-router.go only (stdlib).

Exit 0 means every extracted registration has a consistent classification,
including explicit documentation debt. It does NOT mean complete documentation,
repository coverage, CI integration, or runtime/API correctness.

The deliberately restricted Go reader accepts one SetTaskRouter(*gin.Engine),
literal Group paths, direct HTTP-method registrations, Use, and lexical blocks.
It rejects everything else: helpers, control flow, reassignment, chained calls,
dynamic paths, Any/Match/Handle/Static, inline functions and catch-all wildcards
require an explicit parser extension, never silent omission. Handler selectors
and factory arguments are opaque; references to router/group variables there
are rejected. This is not a Go compiler or a cross-file call-graph analysis.
"""

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import posixpath
import re
import sys

SOURCE = 'router/task-router.go'
FUNCTION = 'SetTaskRouter'
DOCUMENTS = ['docs/openapi/api.json', 'docs/openapi/relay.json']
ISSUE = 'https://github.com/86669666/new-api/issues/3'
METHODS = {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT'}
LEXEME = re.compile(r'(?P<space>\s+)|(?P<comment>//[^\n]*|/\*[\s\S]*?\*/)|'
                    r'(?P<string>"(?:[^"\\\n]|\\.)*"|`[^`]*`)|'
                    r'(?P<word>[A-Za-z_]\w*)|(?P<symbol>:=|[^\s])')


class CoverageError(ValueError):
    pass


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    line: int


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CoverageError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def read_json(path):
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def literal(tokens):
    if len(tokens) != 1 or tokens[0].kind != 'string':
        raise CoverageError('dynamic expression: expected one string literal')
    value = tokens[0].text
    if value.startswith('`'):
        return value[1:-1].replace('\r', '')
    # JSON-compatible Go strings suffice for this profile. Other Go escapes
    # are rejected, rather than guessed or passed through as a different path.
    return json.loads(value)


def gin_join(base, relative):
    # Gin v1.9.1 utils.go:joinPaths uses Go path.Join, preserving a relative
    # trailing slash. Unlike Python join, a leading '/' never discards base.
    if not relative:
        return base
    path = posixpath.normpath('/' + base.strip('/') + '/' + relative)
    path = '/' + path.lstrip('/')
    return path + '/' if relative.endswith('/') and not path.endswith('/') else path


def path_parts(path, oas=False):
    if not isinstance(path, str) or not path.startswith('/') or re.search(r'[\s?#]', path):
        raise CoverageError('invalid absolute path: ' + repr(path))
    parts = path.split('/')
    names = []
    for part in parts:
        pattern = r'\{([A-Za-z_]\w*)\}' if oas else r':([A-Za-z_]\w*)'
        match = re.fullmatch(pattern, part)
        if match:
            names.append(match[1])
        elif any(ch in part for ch in ':*{}'):
            raise CoverageError('unsupported path parameter/catch-all: ' + path)
    if len(names) != len(set(names)):
        raise CoverageError('duplicate path parameter: ' + path)
    return parts, names


def path_shape(path, oas=False):
    parts, _ = path_parts(path, oas)
    return '/'.join('{}' if (p.startswith('{') if oas else p.startswith(':')) else p for p in parts)


class RegistrationReader:
    def __init__(self, source):
        self.tokens = [Token(m.lastgroup, m[0], source.count('\n', 0, m.start()) + 1)
                       for m in LEXEME.finditer(source) if m.lastgroup not in {'space', 'comment'}]
        self.index = 0
        self.scopes = []
        self.routes = []

    def peek(self):
        return self.tokens[self.index].text if self.index < len(self.tokens) else ''

    def take(self, expected=None):
        if self.index == len(self.tokens):
            raise CoverageError('unexpected end of registration source')
        token = self.tokens[self.index]
        if expected is not None and token.text != expected:
            raise CoverageError(f'line {token.line}: expected {expected!r}, got {token.text!r}')
        self.index += 1
        return token

    def arguments(self):
        self.take('(')
        args, current, stack = [], [], []
        while self.peek():
            token = self.take()
            if not stack and token.text == ')':
                if current:
                    args.append(current)
                return args
            if not stack and token.text == ',':
                if not current:
                    raise CoverageError('empty call argument')
                args.append(current)
                current = []
                continue
            if token.text in {'(', '[', '{'}:
                stack.append({'(': ')', '[': ']', '{': '}'}[token.text])
            elif token.text in {')', ']', '}'}:
                if not stack or token.text != stack.pop():
                    raise CoverageError('unbalanced call argument')
            current.append(token)
        raise CoverageError('unterminated call')

    def handlers(self, args):
        groups = {name for scope in self.scopes for name in scope}
        for arg in args:
            if not arg or arg[0].kind != 'word':
                raise CoverageError('unsupported handler expression')
            for token in arg:
                if token.kind == 'word' and token.text in groups | {'func', 'go', 'defer'}:
                    raise CoverageError('router reference/inline registration in opaque handler arguments')
                if token.kind == 'symbol' and token.text in {'{', '}', ':=', '=', ';'}:
                    raise CoverageError('unsupported handler expression')

    def block(self, bindings=None):
        self.take('{')
        self.scopes.append(bindings or {})
        while self.peek() != '}':
            if self.peek() == ';':
                self.take()
                continue
            if self.peek() == '{':
                self.block()
                continue
            name = self.take()
            if name.kind != 'word':
                raise CoverageError(f'line {name.line}: unsupported registration statement')
            assignment = self.peek() == ':='
            target = name.text
            if assignment:
                self.take(':=')
                name = self.take()
            bindings = {k: v for scope in self.scopes for k, v in scope.items()}
            if name.text not in bindings:
                raise CoverageError(f'line {name.line}: unknown receiver/statement {name.text!r}')
            self.take('.')
            method = self.take().text
            args = self.arguments()
            if method == 'Group' and assignment:
                if not args or target in self.scopes[-1]:
                    raise CoverageError('invalid or duplicate group binding')
                self.handlers(args[1:])
                self.scopes[-1][target] = gin_join(bindings[name.text], literal(args[0]))
            elif method == 'Use' and not assignment:
                self.handlers(args)
            elif method in METHODS and not assignment:
                if len(args) < 2:
                    raise CoverageError('route requires literal path and handler')
                self.handlers(args[1:])
                path = gin_join(bindings[name.text], literal(args[0]))
                path_parts(path)
                self.routes.append({'method': method, 'path': path, 'line': name.line})
            else:
                raise CoverageError('unsupported registration expression/method: ' + method)
        self.take('}')
        self.scopes.pop()

    def read(self):
        self.take('package')
        self.take('router')
        self.take('import')
        self.take('(')
        imports = []
        while self.peek() != ')':
            imports.append(literal([self.take()]))
        self.take(')')
        if 'github.com/gin-gonic/gin' not in imports:
            raise CoverageError('missing canonical gin import')
        self.take('func')
        self.take(FUNCTION)
        self.take('(')
        receiver = self.take()
        if receiver.kind != 'word':
            raise CoverageError('invalid engine binding')
        for token in ['*', 'gin', '.', 'Engine', ')']:
            self.take(token)
        self.block({receiver.text: '/'})
        if self.peek():
            raise CoverageError('unsupported top-level declaration after ' + FUNCTION)
        seen, wildcards = set(), {}
        for route in self.routes:
            method, path = route['method'], route['path']
            key = (method, path_shape(path))
            if key in seen:
                raise CoverageError(f'duplicate/conflicting registration: {method} {path}')
            seen.add(key)
            prefix = []
            for part in path.split('/'):
                if part.startswith(':'):
                    key = (method, tuple(prefix))
                    if key in wildcards and wildcards[key] != part:
                        raise CoverageError('conflicting wildcard names: ' + path)
                    wildcards[key] = part
                    part = '{}'
                prefix.append(part)
        return self.routes


def check_coverage(root):
    inventory = read_json(root / 'scripts/openapi/route_coverage.json')
    if (not isinstance(inventory, dict) or set(inventory) != {'version', 'source', 'function', 'documents', 'scope', 'routes'}
            or type(inventory['version']) is not int or inventory['version'] != 1
            or inventory['source'] != SOURCE or inventory['function'] != FUNCTION
            or inventory['documents'] != DOCUMENTS or not isinstance(inventory['scope'], str)
            or not inventory['scope'].strip() or not isinstance(inventory['routes'], list)):
        raise CoverageError('invalid inventory or unsupported scope')
    registrations = RegistrationReader((root / SOURCE).read_text()).read()
    documents = {name: read_json(root / name) for name in DOCUMENTS}
    for name, doc in documents.items():
        if not isinstance(doc, dict) or not isinstance(doc.get('paths'), dict) or doc.get('servers', []) != []:
            raise CoverageError('only explicit root-path OAS documents with empty servers are supported: ' + name)
    classified = {}
    for entry in inventory['routes']:
        if not isinstance(entry, dict):
            raise CoverageError('invalid route classification')
        common = {'method', 'path', 'classification'}
        fields = common | ({'issue', 'reason'} if entry.get('classification') == 'deferred' else {'operation'})
        if set(entry) != fields or entry.get('classification') not in {'deferred', 'documented'}:
            raise CoverageError('invalid route classification fields')
        method, path = entry['method'], entry['path']
        if not isinstance(method, str) or method not in METHODS:
            raise CoverageError('invalid classified method')
        path_parts(path)
        if gin_join('/', path) != path:
            raise CoverageError('classification path must already be canonical')
        key = (method, path)
        if key in classified:
            raise CoverageError('duplicate classification: ' + repr(key))
        if entry['classification'] == 'deferred':
            if entry['issue'] != ISSUE or not isinstance(entry['reason'], str) or not entry['reason'].strip():
                raise CoverageError('deferred route needs issue3 ownership and a concrete reason')
        else:
            binding = entry['operation']
            if (not isinstance(binding, dict) or set(binding) != {'document', 'path', 'parameter_aliases', 'alias_reason'}
                    or binding['document'] not in DOCUMENTS):
                raise CoverageError('invalid documented operation binding')
            _, source_names = path_parts(path)
            _, target_names = path_parts(binding['path'], oas=True)
            aliases, reason = binding['parameter_aliases'], binding['alias_reason']
            if (not isinstance(aliases, dict) or not isinstance(reason, str)
                    or any(k not in source_names or not isinstance(v, str) or v not in target_names for k, v in aliases.items())
                    or aliases and not reason.strip()):
                raise CoverageError('parameter aliases need explicit names and a justification')
            target = '/'.join('{' + aliases.get(p[1:], p[1:]) + '}' if p.startswith(':') else p for p in path.split('/'))
            if target != binding['path']:
                raise CoverageError('operation path differs without a justified parameter alias')
            item = documents[binding['document']]['paths'].get(target, {})
            operation = item.get(method.lower()) if isinstance(item, dict) else None
            if (not isinstance(operation, dict) or not isinstance(operation.get('responses'), dict)
                    or not operation['responses'] or '$ref' in item or '$ref' in operation
                    or item.get('servers', []) != [] or operation.get('servers', []) != []):
                raise CoverageError(f'missing/unsupported OAS operation: {method} {target}')
        classified[key] = entry
    actual = {(r['method'], r['path']) for r in registrations}
    missing, stale = actual - classified.keys(), classified.keys() - actual
    if missing or stale:
        raise CoverageError(f'unclassified registrations: {sorted(missing)}; stale classifications: {sorted(stale)}')
    result = [{**r, **classified[(r['method'], r['path'])]} for r in registrations]
    counts = {state: sum(r['classification'] == state for r in result) for state in ['documented', 'deferred']}
    return {'classification_check_passed': True, 'source': SOURCE, 'function': FUNCTION,
            'route_count': len(result), 'counts': counts, 'routes': result,
            'scope': inventory['scope'], 'normalization': 'Gin Group join; :name -> {name}; only explicitly justified parameter aliases; no prefix/server aliases',
            'complete_documentation': bool(result) and counts['deferred'] == 0,
            'full_repository_coverage': False, 'runtime_verified': False, 'ci_integration': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    try:
        print(json.dumps(check_coverage(args.root), indent=2))
    except (ValueError, OSError) as exc:
        print(json.dumps({'classification_check_passed': False, 'error': str(exc)}), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
