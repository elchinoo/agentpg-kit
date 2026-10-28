import { defineConfig } from '@playwright/test';

/**
 * Real Chrome (the installed Google Chrome, no browser download), 1920x1080, video on. Everything runs against
 * 127.0.0.1. The output (video, timings, screenshots) goes to ./out/, which is git-ignored.
 * RECORD=0 runs the same steps without the video (a rehearsal; faster pacing is not applied, only the file is skipped).
 */
export default defineConfig({
  testDir: '.',
  testMatch: 'record.spec.ts',
  outputDir: './out/playwright',
  workers: 1,
  retries: 0,
  timeout: 20 * 60_000,
  expect: { timeout: 15_000 },
  reporter: [['list']],
  use: {
    channel: 'chrome',
    headless: !process.env.HEADED,
    viewport: { width: 1920, height: 1080 },
    video: process.env.RECORD === '0' ? 'off' : { mode: 'on', size: { width: 1920, height: 1080 } },
    screenshot: 'off',
    trace: 'off',
  },
});
