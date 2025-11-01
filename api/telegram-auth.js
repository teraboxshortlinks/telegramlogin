// ✅ Telegram Auth + Firebase Integration Backend
// 🌐 Deploy on Vercel / Render / Netlify easily

import crypto from "crypto";
import admin from "firebase-admin";

// 🔥 Firebase Admin SDK initialize (only once)
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    }),
  });
}

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;

export default async function handler(req, res) {
  try {
    if (req.method !== "POST") {
      return res.status(405).json({ error: "Only POST requests allowed" });
    }

    const { initData } = req.body;
    if (!initData) {
      return res.status(400).json({ error: "Missing initData" });
    }

    // ✅ Parse Telegram init data
    const parsed = new URLSearchParams(initData);
    const hash = parsed.get("hash");
    parsed.delete("hash");

    const dataCheckArr = [];
    parsed.sort();
    parsed.forEach((v, k) => dataCheckArr.push(`${k}=${v}`));
    const dataCheckString = dataCheckArr.join("\n");

    // ✅ Verify Telegram signature
    const secretKey = crypto
      .createHmac("sha256", "WebAppData")
      .update(BOT_TOKEN)
      .digest();

    const computedHash = crypto
      .createHmac("sha256", secretKey)
      .update(dataCheckString)
      .digest("hex");

    if (computedHash !== hash) {
      return res.status(403).json({ error: "Invalid Telegram signature" });
    }

    const userData = JSON.parse(parsed.get("user"));
    const uid = `tg:${userData.id}`;

    // ✅ Create Firebase custom token
    const customToken = await admin.auth().createCustomToken(uid, {
      telegramId: userData.id,
      first_name: userData.first_name,
      last_name: userData.last_name || "",
      username: userData.username || "",
      photo_url: userData.photo_url || "",
    });

    res.status(200).json({ firebaseToken: customToken });
  } catch (err) {
    console.error("Telegram Auth Error:", err);
    res.status(500).json({ error: err.message });
  }
  }
