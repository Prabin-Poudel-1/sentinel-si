// Pages must bind API to the reviewed Worker; no user-controlled upstream URL.
export async function onRequest({request, env}) {
  if (!env.API) return Response.json({error: 'service_unavailable'}, {status: 503, headers: {'Cache-Control':'no-store'}});
  try { return await env.API.fetch(request); }
  catch { return Response.json({error:'service_unavailable'}, {status:503,headers:{'Cache-Control':'no-store'}}); }
}
