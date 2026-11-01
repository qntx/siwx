/**
 * Bundle entry for the Hermes smoke test. The globals module MUST evaluate before any `src` module
 * (utf8.ts constructs a fatal `TextDecoder` at module load), so `smoke.ts` is imported
 * dynamically.
 */
import { hermesGlobalsInstalled } from "./globals.ts";

declare function print(msg: string): void;
declare function quit(code: number): void;

async function bootstrap(): Promise<void> {
  if (!hermesGlobalsInstalled) {
    throw new Error("smoke: globals module not evaluated");
  }
  const { main } = await import("./smoke.ts");
  await main();
}

// oxlint-disable-next-line unicorn/prefer-top-level-await -- top-level await cannot appear in the iife classic-script bundle Hermes runs
void (async (): Promise<void> => {
  try {
    await bootstrap();
    print("HERMES_SMOKE_OK");
  } catch (error) {
    print(
      `HERMES_SMOKE_FAIL: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}`,
    );
    quit(1);
  }
})();
