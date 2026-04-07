// Netlify Edge Functions 入口
import handler from '../../universal.js';

export default async function (request, context) {
  // Netlify Edge Functions 使用 Deno.env，env 参数可为空
  // context 作为第三个参数传递，用于平台检测和 IP 获取
  return handler.fetch(request, {}, context);
}