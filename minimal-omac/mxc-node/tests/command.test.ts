import test from 'node:test';
import assert from 'node:assert/strict';
import { commandLine } from '../src/command.ts';

test('posix quoting wraps arguments in single quotes', () => {
  assert.equal(commandLine(['echo', 'hi'], 'linux'), "'echo' 'hi'");
  assert.equal(commandLine(["it's"], 'linux'), `'it'\\''s'`);
});

test('windows quoting follows the argv convention', () => {
  assert.equal(commandLine(['echo', 'hi'], 'win32'), 'echo hi');
  assert.equal(commandLine(['a b'], 'win32'), '"a b"');
  assert.equal(commandLine(['say "hi"'], 'win32'), '"say \\"hi\\""');
  assert.equal(commandLine([''], 'win32'), '""');
});
