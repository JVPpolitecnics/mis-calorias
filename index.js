/**
 * Servidor de "Mis calorías" en Node.js (para Hostinger o cualquier hosting con Node 20+).
 *
 * POST /analizar  { image: <base64 JPEG>, mimeType: "image/jpeg" }
 * Cabecera: Authorization: Bearer <token de Firebase del usuario>
 *
 * 1. Comprueba que el token de Firebase es válido (así nadie más puede gastar tu cuota).
 * 2. Envía la foto a Gemini y le pide un JSON con los alimentos.
 * 3. Limpia los números, calcula el total y lo devuelve a la app.
 *
 * La clave de Gemini vive solo aquí (variable de entorno), nunca en el teléfono.
 */
import { existsSync } from 'node:fs';
import { createServer } from 'node:http';
import { createRemoteJWKSet, jwtVerify } from 'jose';

// Carga server/.env si existe (en Hostinger también puedes poner las variables en el panel).
const envFile = new URL('./.env', import.meta.url);
if (existsSync(envFile)) process.loadEnvFile(envFile);

const PORT = Number(process.env.PORT) || 3000;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID;
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-3.5-flash';
// Máximo de fotos por usuario y hora, para que nadie agote tu cuota gratuita.
const MAX_PER_HOUR = Number(process.env.MAX_PER_HOUR) || 60;

if (!GEMINI_API_KEY) console.warn('⚠️  Falta GEMINI_API_KEY');
if (!FIREBASE_PROJECT_ID) console.warn('⚠️  Falta FIREBASE_PROJECT_ID');

const JWKS = createRemoteJWKSet(
  new URL('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com'),
);

const MAX_BODY_BYTES = 6 * 1024 * 1024; // una foto de 1024 px en base64 ocupa ~200-400 KB

const PROMPT = `Eres un nutricionista experto. Analiza la foto de comida.
Identifica cada alimento visible por separado y estima su porción a partir de lo que se ve (tamaño del plato, cubiertos, etc.).
Para cada alimento da: nombre corto en español de España, un emoji que lo represente, la porción estimada (por ejemplo "150 g", "1 unidad · 120 g" o "1 vaso · 200 ml"), kcal, proteína, carbohidratos y grasas en gramos.
Usa valores nutricionales realistas de tablas estándar (BEDCA/USDA). Ten en cuenta las salsas visibles.
ACEITE: si el plato está frito, salteado, a la plancha, guisado, rehogado o aliñado (ensaladas, tostadas, verduras), añade SIEMPRE un alimento aparte llamado "Aceite de oliva" (o el tipo de aceite o grasa que sea más probable, p. ej. "Mantequilla"), emoji 🫒, con los gramos aproximados de aceite que lleva el plato (absorbido + visible), porción con el formato "~10 g · 1 cucharada", y aprox=true. Referencias: 1 cucharada sopera ≈ 10 g ≈ 90 kcal; un frito absorbe ~8-15 g por ración; un salteado o plancha ~5-10 g; un aliño de ensalada ~10-15 g. No cuentes ese aceite dentro de los demás alimentos (para no contarlo dos veces). Si el plato no lleva aceite ni grasa añadida (fruta, yogur, cocido al vapor…), no añadas esa línea.
Para el resto de alimentos pon aprox=false.
"plato" es un nombre corto para toda la comida (por ejemplo "Pollo con arroz y ensalada").
Si en la foto no hay comida ni bebida, pon esComida=false y alimentos vacío.
Responde solo con el JSON.`;

const ITEM_KEYS = ['nombre', 'emoji', 'porcion', 'kcal', 'proteina', 'carbohidratos', 'grasas', 'aprox'];
const SCHEMA = {
  type: 'OBJECT',
  properties: {
    esComida: { type: 'BOOLEAN' },
    plato: { type: 'STRING' },
    alimentos: {
      type: 'ARRAY',
      items: {
        type: 'OBJECT',
        properties: {
          nombre: { type: 'STRING' },
          emoji: { type: 'STRING' },
          porcion: { type: 'STRING' },
          kcal: { type: 'NUMBER' },
          proteina: { type: 'NUMBER' },
          carbohidratos: { type: 'NUMBER' },
          grasas: { type: 'NUMBER' },
          aprox: { type: 'BOOLEAN' },
        },
        required: ITEM_KEYS,
        propertyOrdering: ITEM_KEYS,
      },
    },
  },
  required: ['esComida', 'plato', 'alimentos'],
  propertyOrdering: ['esComida', 'plato', 'alimentos'],
};

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function send(res, status, body) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  });
  res.end(body === null ? undefined : JSON.stringify(body));
}

async function readJson(req) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new HttpError(413, 'La foto es demasiado grande.');
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpError(400, 'Petición no válida.');
  }
}

async function verifyFirebaseToken(token) {
  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: `https://securetoken.google.com/${FIREBASE_PROJECT_ID}`,
      audience: FIREBASE_PROJECT_ID,
      algorithms: ['RS256'],
    });
    if (!payload.sub) throw new Error('sin usuario');
    return payload.sub;
  } catch {
    throw new HttpError(401, 'Tu sesión ha caducado. Vuelve a iniciar sesión.');
  }
}

// Límite sencillo en memoria: fotos por usuario en la última hora.
const usage = new Map();
function checkRateLimit(uid) {
  const now = Date.now();
  const recent = (usage.get(uid) ?? []).filter((t) => now - t < 3600_000);
  if (recent.length >= MAX_PER_HOUR) throw new HttpError(429, 'Has escaneado muchas fotos seguidas. Espera un rato.');
  recent.push(now);
  usage.set(uid, recent);
}

const num = (v) => {
  const n = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(n) && n >= 0 ? Math.round(n) : 0;
};

export function clean(raw) {
  const alimentos = (Array.isArray(raw?.alimentos) ? raw.alimentos : [])
    .map((a) => ({
      nombre: String(a?.nombre ?? '').slice(0, 80) || 'Alimento',
      emoji: String(a?.emoji ?? '🍽️').slice(0, 8),
      porcion: String(a?.porcion ?? '').slice(0, 40),
      kcal: num(a?.kcal),
      proteina: num(a?.proteina),
      carbohidratos: num(a?.carbohidratos),
      grasas: num(a?.grasas),
      ...(a?.aprox === true ? { aprox: true } : {}),
    }))
    .slice(0, 20);
  const total = alimentos.reduce(
    (t, a) => ({
      kcal: t.kcal + a.kcal,
      proteina: t.proteina + a.proteina,
      carbohidratos: t.carbohidratos + a.carbohidratos,
      grasas: t.grasas + a.grasas,
    }),
    { kcal: 0, proteina: 0, carbohidratos: 0, grasas: 0 },
  );
  return {
    esComida: raw?.esComida !== false && alimentos.length > 0,
    plato: String(raw?.plato ?? '').slice(0, 80),
    alimentos,
    total,
  };
}

async function askGemini(image, mimeType) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(GEMINI_MODEL)}:generateContent`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-goog-api-key': GEMINI_API_KEY },
    body: JSON.stringify({
      contents: [{ role: 'user', parts: [{ inlineData: { mimeType, data: image } }, { text: PROMPT }] }],
      generationConfig: { responseMimeType: 'application/json', responseSchema: SCHEMA, temperature: 0.2 },
    }),
    signal: AbortSignal.timeout(60_000),
  });
  if (!res.ok) {
    const detail = await res.text();
    console.error('Gemini error', res.status, detail.slice(0, 500));
    if (res.status === 429) throw new HttpError(429, 'Se ha alcanzado el límite gratuito de Gemini. Prueba en un rato.');
    throw new HttpError(502, 'El servicio de análisis no respondió bien. Inténtalo de nuevo.');
  }
  const data = await res.json();
  const text = data?.candidates?.[0]?.content?.parts?.map((p) => p.text ?? '').join('') ?? '';
  try {
    return JSON.parse(text.replace(/^```(json)?|```$/g, '').trim());
  } catch {
    console.error('JSON inválido de Gemini', text.slice(0, 500));
    throw new HttpError(502, 'No pude entender la respuesta del análisis. Inténtalo de nuevo.');
  }
}

async function handle(req, res) {
  const { pathname } = new URL(req.url, 'http://localhost');
  if (req.method === 'OPTIONS') return send(res, 204, null);
  if (req.method === 'GET' && (pathname === '/' || pathname === '/salud')) {
    return send(res, 200, { ok: true, servicio: 'calorias-api', modelo: GEMINI_MODEL, configurado: !!(GEMINI_API_KEY && FIREBASE_PROJECT_ID) });
  }
  if (pathname !== '/analizar' || req.method !== 'POST') return send(res, 404, { error: 'No encontrado' });

  if (!GEMINI_API_KEY || !FIREBASE_PROJECT_ID) throw new HttpError(500, 'Falta configurar GEMINI_API_KEY o FIREBASE_PROJECT_ID en el servidor.');

  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  if (!token) throw new HttpError(401, 'Tienes que iniciar sesión.');
  const uid = await verifyFirebaseToken(token);
  checkRateLimit(uid);

  const body = await readJson(req);
  const image = typeof body?.image === 'string' ? body.image : '';
  const mimeType = ['image/jpeg', 'image/png', 'image/webp'].includes(body?.mimeType) ? body.mimeType : 'image/jpeg';
  if (!image) throw new HttpError(400, 'Falta la foto.');

  const raw = await askGemini(image, mimeType);
  send(res, 200, clean(raw));
}

export const server = createServer((req, res) => {
  handle(req, res).catch((e) => {
    if (e instanceof HttpError) return send(res, e.status, { error: e.message });
    console.error(e);
    send(res, 500, { error: 'Error inesperado del servidor.' });
  });
});

if (process.env.NODE_ENV !== 'test') {
  server.listen(PORT, () => console.log(`calorias-api escuchando en el puerto ${PORT}`));
}
