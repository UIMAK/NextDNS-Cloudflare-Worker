// Vercel Edge Functions 入口
import { onRequest } from '../universal.js';
export { config } from '../universal.js';

// Vercel default export 签名为 (request: Request) => Response，
// 而 onRequest 签名为 ({ request, env }) => Response，做薄包装适配
export default function (request) {
  return onRequest({ request, env: process.env });
}
