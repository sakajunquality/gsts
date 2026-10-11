import { post, fail } from './runtime.mjs';
try { await post(); } catch (error) { fail(error); }
