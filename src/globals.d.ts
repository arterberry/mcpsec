declare var console: any;
declare var process: any;
declare function require(path: string): any;
declare var module: any;
declare var __dirname: string;
declare function setTimeout(handler: (...args: any[]) => void, timeout?: number, ...args: any[]): any;

declare module 'fs';
declare module 'path';
declare module 'os';
declare module 'child_process';
declare module 'commander';
declare module 'chalk';
declare module 'typescript' {
  const ts: any;
  export = ts;
}
