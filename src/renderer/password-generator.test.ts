import test from "node:test";
import assert from "node:assert/strict";

import { generatePassword, type PasswordGeneratorOptions } from "./password-generator";

const allOptions: PasswordGeneratorOptions = {
  length: 24,
  uppercase: true,
  lowercase: true,
  numbers: true,
  symbols: true,
};

test("generates the requested length and includes every enabled character group", () => {
  const password = generatePassword(allOptions);

  assert.equal(password.length, 24);
  assert.match(password, /[A-Z]/);
  assert.match(password, /[a-z]/);
  assert.match(password, /[2-9]/);
  assert.match(password, /[!@#$%^&*()\-_=+\[\]{};:,.?]/);
});

test("generates passwords using only the selected character group", () => {
  const password = generatePassword({
    length: 16,
    uppercase: false,
    lowercase: true,
    numbers: false,
    symbols: false,
  });

  assert.match(password, /^[a-z]+$/);
});

test("rejects a configuration with no character groups", () => {
  assert.throws(
    () => generatePassword({ ...allOptions, uppercase: false, lowercase: false, numbers: false, symbols: false }),
    /at least one character group/,
  );
});

test("rejects lengths outside the supported range", () => {
  assert.throws(() => generatePassword({ ...allOptions, length: 7 }), /between 8 and 64/);
  assert.throws(() => generatePassword({ ...allOptions, length: 65 }), /between 8 and 64/);
});
