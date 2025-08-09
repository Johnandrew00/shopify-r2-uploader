import crypto from "crypto";
import { S3Client, PutObjectCommand, GetObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

const {
  SHOPIFY_API_SECRET,
  R2_ACCOUNT_ID,
  R2_ACCESS_KEY_ID,
  R2_SECRET_ACCESS_KEY,
  R2_BUCKET,
  R2_PUBLIC_HOST
} = process.env;

function verifyProxy(q) {
  const { signature, timestamp, shop, path_prefix } = q || {};
  if (!signature || !timestamp || !shop || !path_prefix) return false;
  const msg = `${shop}${path_prefix}${timestamp}`;
  const calc = crypto.createHmac("sha256", SHOPIFY_API_SECRET).update(msg).digest("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(calc, "hex"), Buffer.from(signature, "hex"));
  } catch {
    return false;
  }
}

const s3 = new S3Client({
  region: "auto",
  endpoint: `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: { accessKeyId: R2_ACCESS_KEY_ID, secretAccessKey: R2_SECRET_ACCESS_KEY },
  forcePathStyle: true
});

const MAX_BYTES = 25 * 1024 * 1024;
const ALLOWED = new Set(["image/jpeg","image/png","image/webp","application/pdf"]);

export default async function handler(req, res) {
  if (!verifyProxy(req.query)) return res.status(401).json({ error: "Invalid proxy signature" });

  const ct = String(req.query.ct || "application/octet-stream");
  const size = Number(req.query.size || 0);
  const ext = String(req.query.ext || "bin").replace(/[^a-z0-9.]/gi, "").slice(0, 10) || "bin";
  if (!ALLOWED.has(ct)) return res.status(400).json({ error: "Type not allowed" });
  if (size > MAX_BYTES) return res.status(400).json({ error: "File too large" });

  const key = `contact/${Date.now()}-${crypto.randomBytes(6).toString("hex")}.${ext}`;

  const put = new PutObjectCommand({ Bucket: R2_BUCKET, Key: key, ContentType: ct });
  const putUrl = await getSignedUrl(s3, put, { expiresIn: 60 });

  const get = new GetObjectCommand({ Bucket: R2_BUCKET, Key: key });
  const signedGetUrl = await getSignedUrl(s3, get, { expiresIn: 7 * 24 * 3600 });

  const cdnUrl = R2_PUBLIC_HOST ? `https://${R2_PUBLIC_HOST}/${key}` : null;
  res.setHeader("Cache-Control", "no-store");
  res.status(200).json({ putUrl, key, signedGetUrl, cdnUrl });
}
