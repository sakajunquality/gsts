import { main, fail } from './runtime.mjs';
try { await main(); } catch (error) { fail(error); }
