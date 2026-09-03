const specials = "!@#$%^&*()-_=+";
const lowercase = "abcdefghijklmnopqrstuvwxyz";
const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const numbers = "0123456789";
const all = specials + lowercase + uppercase + numbers;

function pick(source: string, count: number): string {
  let chars = "";
  for (let i = 0; i < count; i++) {
    chars += source.charAt(Math.floor(Math.random() * source.length));
  }
  return chars;
}

function shuffle(value: string): string {
  const array = value.split("");
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    const current = array[i];
    const swap = array[j];
    if (current === undefined || swap === undefined) continue;
    array[i] = swap;
    array[j] = current;
  }
  return array.join("");
}

export function randomPassword(): string {
  const password =
    pick(specials, 2) +
    pick(lowercase, 3) +
    pick(uppercase, 3) +
    pick(numbers, 3) +
    pick(all, 5);
  return shuffle(password);
}
