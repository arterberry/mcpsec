// src/globals.d.ts
import 'node';

declare global {
  var console: Console;
  var process: NodeJS.Process;
  var __dirname: string;
  var module: NodeModule;
}

export {};
