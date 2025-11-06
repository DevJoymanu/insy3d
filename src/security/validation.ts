export function whitelistInput(input: string, regex: RegExp): string | null {
  return regex.test(input) ? input : null;
}
