import { createServer } from 'vite';

// Use the same configuration for npm run dev and Vercel's service dev command.
const server = await createServer();

await server.listen();
server.printUrls();
server.bindCLIShortcuts({ print: true });
