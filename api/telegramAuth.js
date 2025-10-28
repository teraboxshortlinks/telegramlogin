// api/telegramAuth.js - Vercel/Netlify Serverless Function

const admin = require('firebase-admin');
const crypto = require('crypto');
const url = require('url');

// Environment Variables (Vercel/Netlify Dashboard থেকে সেট করতে হবে)
const BOT_TOKEN = process.env.BOT_TOKEN;
const FIREBASE_SERVICE_ACCOUNT_JSON = process.env.FIREBASE_SERVICE_ACCOUNT_JSON_BASE64; 

// --------------------------------------------------------------------------
// Firebase Admin SDK Initialize করা
// --------------------------------------------------------------------------
let firebaseAppInitialized = false;
if (BOT_TOKEN && FIREBASE_SERVICE_ACCOUNT_JSON) {
    try {
        // Base64 থেকে JSON এ রূপান্তর
        const serviceAccountJson = JSON.parse(Buffer.from(FIREBASE_SERVICE_ACCOUNT_JSON, 'base64').toString('utf8'));
        
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccountJson)
        });
        firebaseAppInitialized = true;
        console.log("Firebase Admin SDK initialized.");
    } catch (error) {
        console.error("Failed to initialize Firebase Admin SDK:", error.message);
    }
} else {
    console.error("FATAL: Environment variables (BOT_TOKEN or Service Account) are missing.");
}


// --------------------------------------------------------------------------
// Telegram initData ভেরিফিকেশন লজিক
// --------------------------------------------------------------------------
function verifyTelegramInitData(initData) {
    if (!BOT_TOKEN) return null;

    try {
        const data = new URLSearchParams(initData);
        const hash = data.get('hash');
        if (!hash) return null;
        data.delete('hash');

        const dataCheckArr = [...data.entries()]
            .map(([key, value]) => `${key}=${decodeURIComponent(value)}`)
            .sort();
        
        const dataCheckString = dataCheckArr.join('\n');

        // Secret Key তৈরি করা: HMAC-SHA256(BOT_TOKEN, 'WebAppData')
        const secretKey = crypto
            .createHmac('sha256', 'WebAppData')
            .update(BOT_TOKEN)
            .digest();

        // ডেটা চেক হ্যাশ জেনারেট করা: HMAC-SHA256(secretKey, dataCheckString)
        const calculatedHash = crypto
            .createHmac('sha256', secretKey)
            .update(dataCheckString)
            .digest('hex');

        if (calculatedHash === hash) {
            const userDataString = data.get('user');
            if (userDataString) {
                // ভেরিফিকেশন সফল হলে ইউজার ডেটা রিটার্ন করা
                return JSON.parse(decodeURIComponent(userDataString));
            }
        }
    } catch (e) {
        console.error("Error during initData verification:", e);
        return null;
    }
    return null;
}

// --------------------------------------------------------------------------
// API এন্ডপয়েন্ট হ্যান্ডলার
// --------------------------------------------------------------------------
module.exports = async (req, res) => {
    // শুধুমাত্র POST রিকোয়েস্ট অনুমোদন করা
    if (req.method !== 'POST') {
        return res.status(405).send('Method Not Allowed');
    }

    if (!firebaseAppInitialized) {
        return res.status(500).send({ error: 'Server configuration error' });
    }

    // Request Body থেকে initData নেওয়া
    let initData;
    try {
        // Vercel/Netlify-এর জন্য বডি পার্সিং
        if (typeof req.body === 'string') {
            initData = JSON.parse(req.body).initData;
        } else {
            initData = req.body.initData;
        }
    } catch (e) {
        return res.status(400).send({ error: 'Invalid JSON body' });
    }

    if (!initData) {
        return res.status(400).send({ error: 'initData missing in request body' });
    }

    // 1. initData ভেরিফাই করা
    const telegramUser = verifyTelegramInitData(initData);

    if (!telegramUser) {
        return res.status(401).send({ error: 'Invalid or Tampered Telegram Init Data' });
    }

    try {
        const uid = String(telegramUser.id);
        
        // Firebase-এ ইউজারকে তৈরি করা (যদি না থাকে)
        const displayName = telegramUser.first_name + (telegramUser.last_name ? ` ${telegramUser.last_name}` : '');
        
        try {
            await admin.auth().getUser(uid);
        } catch (error) {
            if (error.code === 'auth/user-not-found') {
                await admin.auth().createUser({
                    uid: uid,
                    displayName: displayName,
                    photoURL: telegramUser.photo_url || null,
                });
                console.log(`New user created: ${uid}`);
            } else {
                throw error;
            }
        }

        // 2. Firebase Custom Token জেনারেট করা
        const firebaseToken = await admin.auth().createCustomToken(uid);

        // 3. ক্লায়েন্টের কাছে টোকেন পাঠানো
        res.status(200).send({ firebaseToken: firebaseToken });

    } catch (error) {
        console.error("Error during Firebase custom token generation:", error);
        res.status(500).send({ error: 'Internal Server Error during authentication' });
    }
};
