#!/usr/bin/env python3
"""Offline pre-publication guard for every explicit manifest or staged index byte.

No file contents, private paths, or credentials are printed. This bounded check
supplements human privacy review and dedicated scanners; it is not proof that
unknown or encoded personal material is absent. No files or Git state are changed.
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys
from collections import Counter

MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_FILES = 10000
# Exact independently reviewed generic template and official wrapper bytes.
REVIEWED = {
    '.env.example': '8eccab9dfd1071e5f6e5a1ca30000e0f87b4d87ed4bc5399f4474053798f7211',
    'gradle/wrapper/gradle-wrapper.jar': 'ad16bca46cb71bb5887c546860d93992aeee35c1fdaf4a242b0a612375d937e0',
}
PRIVATE_PARTS = {'.git', '.secrets', '.private', '.local', '.agents', '.codex', '.claude', '.cursor', '.skills', '.ai', '.aws', '.continue', '.windsurf', '.roo', '.cline', '.clinerules', '.kilocode', '.opencode', '.gemini', '.kiro', '.serena', 'private-prompts', 'personal-skills', 'prompts', 'skills', 'user_notes', 'agent_notes', 'attachments', 'finsec-inputs', 'source-pack', 'finsec-dev'}
PRIVATE_NAMES = {'.cursorrules', '.windsurfrules', '.mcp.json', 'mcp.json', 'opencode.json', 'opencode.jsonc', 'copilot-instructions.md', 'model.lock.json', 'model-manifest.json', 'model.manifest.json', 'modelpath', 'local-config.json'}
PRIVATE_SUFFIXES = {'.pem', '.key', '.p12', '.pfx', '.sqlite', '.sqlite3', '.db', '.safetensors', '.gguf', '.ckpt', '.pt', '.pth', '.docx', '.pdf', '.zip'}
HOME = re.compile(r'(?:/(?:Users|home)/[A-Za-z0-9_.-]+|[A-Za-z]:[\\/]+Users[\\/]+[A-Za-z0-9_.-]+)')
EMAIL = re.compile(r'(?<![\w.+-])[A-Za-z0-9_.+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b')
TOKENS = [re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'), re.compile(r'AKIA[0-9A-Z]{16}'), re.compile(r'gh[pousr]_[A-Za-z0-9]{30,}'), re.compile(r'sk-(?:proj-)?[A-Za-z0-9_-]{40,}')]

class Blocked(ValueError):
    pass


def safe_path(value):
    if not isinstance(value, str) or not value or '\\' in value or '\x00' in value or any(ord(c) < 32 for c in value):
        raise Blocked('invalid_path')
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or any(part in {'', '.', '..'} for part in value.split('/')) or ':' in value:
        raise Blocked('invalid_path')
    return path


def path_reason(name):
    path = safe_path(name)
    folded = name.casefold()
    base = path.name.casefold()
    parts = {part.casefold() for part in path.parts}
    if name != '.env.example' and (base == '.env' or base.startswith('.env.') or base.endswith('.env') or '.env.' in base):
        return 'environment_file'
    if parts & PRIVATE_PARTS or base in PRIVATE_NAMES or path.suffix.casefold() in PRIVATE_SUFFIXES:
        return 'private_material_path'
    if re.match(r'^(agents?|skills?|claude|gemini).*\.md$', base) or base.startswith('.aider') or '.prompt' in base:
        return 'private_instruction_path'
    if folded.startswith(('.github/instructions/', '.github/prompts/', '.github/agents/', 'docs/work/')):
        return 'private_instruction_path'
    if 'finsec_fuse_' in folded and ('v2.1' in folded or '프롬프트' in folded or '프롬프트' in folded):
        return 'private_source_path'
    return None


def inspect_bytes(name, data):
    reason = path_reason(name)
    if reason:
        return reason
    if name in REVIEWED:
        return None if hashlib.sha256(data).hexdigest() == REVIEWED[name] else 'reviewed_file_changed'
    try:
        content = data.decode('utf-8')
    except UnicodeError:
        return 'unreviewed_binary'
    if '\x00' in content:
        return 'unreviewed_binary'
    if HOME.search(content):
        return 'personal_home_path'
    if any(pattern.search(content) for pattern in TOKENS):
        return 'potential_credential'
    for match in EMAIL.finditer(content):
        domain = match.group(1).lower()
        if domain not in {'example.com', 'example.org', 'example.net'} and not domain.endswith(('.test', '.invalid', '.example')):
            return 'personal_email_requires_review'
    return None


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Blocked('duplicate_json_key')
        result[key] = value
    return result


def manifest_entries(root, manifest):
    if manifest.is_symlink() or manifest.stat().st_size > MAX_FILE:
        raise Blocked('invalid_manifest')
    document = json.loads(manifest.read_bytes(), object_pairs_hook=no_duplicates)
    if isinstance(document, dict):
        keys = [key for key in ('files', 'manifest') if key in document]
        if len(keys) != 1:
            raise Blocked('invalid_manifest')
        document = document[keys[0]]
    if not isinstance(document, list) or not 0 < len(document) <= MAX_FILES:
        raise Blocked('invalid_manifest')
    for record in document:
        if not isinstance(record, dict) or not {'path', 'sha256', 'size'} <= record.keys():
            raise Blocked('invalid_manifest_record')
        path = safe_path(record['path'])
        if record.get('mode', '100644') not in {'100644', '100755'}:
            raise Blocked('nonregular_file')
        if type(record['size']) is not int or not 0 <= record['size'] <= MAX_FILE or not isinstance(record['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', record['sha256']):
            raise Blocked('invalid_manifest_record')
        target = root
        for part in path.parts:
            target = target / part
            if target.is_symlink():
                raise Blocked('symlink')
        if not target.is_file() or target.stat().st_size != record['size']:
            raise Blocked('manifest_size_mismatch')
        data = target.read_bytes()
        if len(data) > MAX_FILE or hashlib.sha256(data).hexdigest() != record['sha256']:
            raise Blocked('manifest_hash_mismatch')
        yield str(path), data


def git(root, *args):
    result = subprocess.run(['git', *args], cwd=root, capture_output=True, check=False)
    if result.returncode:
        raise Blocked('index_read_failed')
    return result.stdout


def index_entries(root):
    """Read staged blob objects, including ignored-but-tracked files, not worktree bytes."""
    top = pathlib.Path(git(root, 'rev-parse', '--show-toplevel').decode('utf-8').strip()).resolve()
    if root.resolve() != top:
        raise Blocked('index_root_must_be_repository_top')
    rows = git(root, 'ls-files', '--stage', '-z').split(b'\0')
    if len(rows) > MAX_FILES + 1:
        raise Blocked('too_many_files')
    for row in rows:
        if not row:
            continue
        metadata, name = row.split(b'\t', 1)
        mode, oid, stage = metadata.decode('ascii').split()
        if mode not in {'100644', '100755'} or stage != '0' or not re.fullmatch('[0-9a-f]{40,64}', oid):
            raise Blocked('nonregular_or_unmerged_index')
        name = str(safe_path(name.decode('utf-8')))
        size = int(git(root, 'cat-file', '-s', oid))
        if size > MAX_FILE:
            raise Blocked('oversize_file')
        yield name, git(root, 'cat-file', 'blob', oid)


def check(entries):
    errors = Counter()
    seen = set()
    total = 0
    for name, data in entries:
        if name in seen:
            raise Blocked('duplicate_path')
        seen.add(name)
        total += len(data)
        if len(seen) > MAX_FILES or len(data) > MAX_FILE or total > MAX_TOTAL:
            raise Blocked('scan_bound_exceeded')
        reason = inspect_bytes(name, data)
        if reason:
            errors[reason] += 1
    if not seen:
        raise Blocked('empty_inventory')
    return len(seen), errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--manifest', type=pathlib.Path, help='exact reviewed candidate inventory with path, size, SHA-256')
    mode.add_argument('--index', action='store_true', help='inspect every currently staged Git blob')
    args = parser.parse_args(argv)
    try:
        root = args.root.resolve(strict=True)
        count, errors = check(manifest_entries(root, args.manifest) if args.manifest else index_entries(root))
        if errors:
            print(json.dumps({'status': 'BLOCKED', 'files': count, 'reasons': dict(sorted(errors.items()))}))
            return 1
        print(json.dumps({'status': 'PASS', 'files': count, 'scope': 'exact supplied inventory; human privacy review still required'}))
        return 0
    except (Blocked, OSError, ValueError, TypeError, KeyError, UnicodeError, subprocess.SubprocessError):
        print('{"status":"BLOCKED","reason":"inventory_or_scan_failed"}')
        return 1


if __name__ == '__main__':
    sys.exit(main())
