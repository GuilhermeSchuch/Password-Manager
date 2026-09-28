export const PASSWORD_LENGTH_MIN = 8;
export const PASSWORD_LENGTH_MAX = 64;

export type PasswordGeneratorOptions = {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
};

const CHARACTER_POOLS = {
  uppercase: "ABCDEFGHJKLMNPQRSTUVWXYZ",
  lowercase: "abcdefghijkmnopqrstuvwxyz",
  numbers: "23456789",
  symbols: "!@#$%^&*()-_=+[]{};:,.?",
} as const;

type CharacterGroup = keyof typeof CHARACTER_POOLS;

function randomIndex(maximum: number): number {
  const limit = 0x100000000 - (0x100000000 % maximum);
  const values = new Uint32Array(1);
  do {
    globalThis.crypto.getRandomValues(values);
  } while (values[0] >= limit);
  return values[0] % maximum;
}

export function generatePassword(options: PasswordGeneratorOptions): string {
  if (!Number.isInteger(options.length) || options.length < PASSWORD_LENGTH_MIN || options.length > PASSWORD_LENGTH_MAX) {
    throw new Error(`Password length must be between ${PASSWORD_LENGTH_MIN} and ${PASSWORD_LENGTH_MAX}.`);
  }

  const enabledGroups = (Object.keys(CHARACTER_POOLS) as CharacterGroup[]).filter((group) => options[group]);
  if (enabledGroups.length === 0) {
    throw new Error("Select at least one character group.");
  }

  const pools = enabledGroups.map((group) => CHARACTER_POOLS[group]);
  const allCharacters = pools.join("");
  const characters = pools.map((pool) => pool[randomIndex(pool.length)]);

  while (characters.length < options.length) {
    characters.push(allCharacters[randomIndex(allCharacters.length)]);
  }

  for (let index = characters.length - 1; index > 0; index -= 1) {
    const swapIndex = randomIndex(index + 1);
    [characters[index], characters[swapIndex]] = [characters[swapIndex], characters[index]];
  }

  return characters.join("");
}
