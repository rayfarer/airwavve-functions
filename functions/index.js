const functions = require('firebase-functions');
const admin = require('firebase-admin');
const Stripe = require('stripe');

const { onCall } = require('firebase-functions/v2/https');
const { defineString } = require('firebase-functions/params');
const axios = require('axios');
const querystring = require('querystring');

const SPOTIFY_CLIENT_ID = '8ffda13719d24c588152a778a5e95697';
const SPOTIFY_CLIENT_SECRET = functions.config().spotifysecret.key;
const REDIRECT_URI = 'https://us-central1-airwavve-d98b8.cloudfunctions.net/spotifyAuthCallback';

const openaiApiKey = functions.config().openai.key; // <-- Make sure you set this using `firebase functions:config:set openai.key="YOUR-KEY"`


const IS_DEV = process.env.NODE_ENV !== 'production';
const frontendURL = process.env.FRONTEND_URL || (IS_DEV ? 'http://localhost:5173' : 'https://airwavve.com');

// Make sure you set this in functions config: 
// firebase functions:config:set elevenlabs.api_key="your_api_key_here"
const elevenLabsApiKey = functions.config().elevenlabs.api_key;
admin.initializeApp();

// Pull your Stripe secret & webhook secret from functions config:
//   firebase functions:config:set stripe.secret="sk_…" stripe.webhook_secret="whsec_…"
const stripe = new Stripe(functions.config().stripe.secret);
const endpointSecret = functions.config().stripe.webhook_secret;

// 1. onCreate: initialize new user's token bucket in Realtime Database
// 1. onCreate: initialize new user's token bucket in **Cloud Firestore**
exports.newUser = functions.auth.user().onCreate((user) => {
    const uid = user.uid;
    return admin
        .firestore()
        .collection('users')
        .doc(uid)
        .set({
            maxTokens: 5000,
            tokens: 5000,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            subscribed: false
        })
        .then(() => {
            console.log(`User ${uid} initialized with 5000 tokens`);
            return null;
        })
        .catch((error) => {
            console.error("Error creating user data:", error);
            return null;
        });
});


// 2. checkTokens: callable, returns current token balance
exports.checkTokens = functions.https.onCall(async (data, context) => {
    if (!context.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'User must be authenticated.');
    }
    const uid = data.uid;
    if (!uid) {
        throw new functions.https.HttpsError('invalid-argument', 'Please provide a user ID.');
    }

    const userRef = admin.firestore().collection('users').doc(uid);
    const userDoc = await userRef.get();
    if (!userDoc.exists) {
        throw new functions.https.HttpsError('not-found', 'User not found.');
    }

    const tokens = userDoc.data().tokens || 0;
    return { success: true, tokens };
});

// 3. deductTokens: callable, subtracts tokens based on textLength
exports.deductTokens = functions.https.onCall(async (data, context) => {
    if (!context.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'User must be authenticated.');
    }
    const { uid, textLength } = data;
    if (!uid || textLength == null) {
        throw new functions.https.HttpsError(
            'invalid-argument',
            'Must provide uid and textLength.'
        );
    }

    const deduction = textLength * 0.5;
    const userRef = admin.firestore().collection('users').doc(uid);
    const userDoc = await userRef.get();
    if (!userDoc.exists) {
        throw new functions.https.HttpsError('not-found', 'User not found.');
    }

    const current = userDoc.data().tokens || 0;
    if (current < deduction) {
        throw new functions.https.HttpsError('out-of-range', 'Insufficient tokens.', {
            userTokens: current,
            deduction
        });
    }

    const newBalance = current - deduction;
    await userRef.update({ tokens: newBalance });
    return { success: true, newTokens: newBalance };
});

// 4. Stripe webhook: listens for successful payments and adds tokens
exports.handleStripeWebhook = functions.https.onRequest(async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        event = stripe.webhooks.constructEvent(req.rawBody, sig, endpointSecret);
    } catch (err) {
        console.error('⚠️ Webhook signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;

        // for Payment Links, we passed uid in client_reference_id
        const uid = session.client_reference_id;
        // if you also set metadata.tokens on the link, grab it; else use a fixed amount
        const addedTokens = 5000;


        if (uid && addedTokens > 0) {
            const userRef = admin.firestore().collection('users').doc(uid);

            try {
                await admin.firestore().runTransaction(async (tx) => {
                    const snap = await tx.get(userRef);
                    if (!snap.exists) throw new Error('User not found in Firestore');

                    const { tokens: curr, maxTokens: currMax } = snap.data();
                    const newTokens = (curr || 0) + addedTokens;
                    const newMaxTokens = (currMax || 0) + addedTokens;

                    tx.update(userRef, {
                        tokens: newTokens,
                        maxTokens: newMaxTokens
                    });
                });
                console.log(`Added ${addedTokens} tokens to ${uid} (tokens & maxTokens bumped).`);
            } catch (err) {
                console.error('Error updating tokens after payment:', err);
            }
        }
    }

    // Acknowledge receipt
    res.status(200).send('Received');
});

exports.getElevenlabsTts = functions.https.onCall(async (data, context) => {
    if (!context.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'User must be authenticated.');
    }

    const { uid } = context.auth;
    const { text, voiceId } = data;
    if (!text || !voiceId) {
        throw new functions.https.HttpsError('invalid-argument', 'Must provide text and voiceId.');
    }

    const userRef = admin.firestore().collection('users').doc(uid);
    const userDoc = await userRef.get();
    if (!userDoc.exists) {
        throw new functions.https.HttpsError('not-found', 'User not found.');
    }

    const userTokens = userDoc.data().tokens || 0;
    const requiredTokens = text.length * 0.5;
    if (userTokens < requiredTokens) {
        throw new functions.https.HttpsError(
            'out-of-range',
            'Insufficient tokens.',
            { userTokens, requiredTokens }
        );
    }

    try {
        const ttsResponse = await axios({
            method: 'post',
            url: `https://api.elevenlabs.io/v1/text-to-speech/${voiceId}`,
            headers: {
                'xi-api-key': elevenLabsApiKey,
                'Content-Type': 'application/json',
            },
            responseType: 'arraybuffer',
            data: {
                text,
                model_id: 'eleven_multilingual_v2',
                voice_settings: { stability: 0.5, similarity_boost: 0.5 }
            }
        });

        const contentType = ttsResponse.headers['content-type'] || '';
        if (!contentType.startsWith('audio/')) {
            // if it's not audio, log the body (likely a JSON error) and abort
            const errorText = Buffer.from(ttsResponse.data).toString('utf8');
            console.error('❌ ElevenLabs returned non-audio payload:', errorText);
            throw new functions.https.HttpsError(
                'internal',
                'ElevenLabs TTS did not return audio.'
            );
        }

        const audioBuffer = ttsResponse.data;
        // Deduct tokens only once we know it worked
        await userRef.update({
            tokens: admin.firestore.FieldValue.increment(-requiredTokens)
        });

        const base64Audio = Buffer.from(audioBuffer).toString('base64');
        return {
            success: true,
            audioBase64: base64Audio,
            sampleRate: 22050  // match what your client expects
        };

    } catch (err) {
        console.error('🔥 Error calling ElevenLabs:', err);
        throw new functions.https.HttpsError('internal', 'Failed to generate TTS.');
    }
});

exports.spotifyAuthCallback = functions.https.onRequest(async (req, res) => {
    const code = req.query.code || null;
    const state = req.query.state || null;

    if (!code) {
        return res.status(400).send('Authorization code is missing.');
    }
    if (!state) {
        return res.status(400).send('State parameter missing.');
    }

    let uid, env;
    try {
        const parsedState = JSON.parse(state);
        uid = parsedState.uid;
        env = parsedState.env || 'prod'; // Default to prod if missing

        if (!uid) {
            throw new Error('UID missing inside state.');
        }
    } catch (error) {
        console.error('Error parsing state:', error);
        return res.status(400).send('Invalid state.');
    }

    try {
        const tokenResponse = await axios.post('https://accounts.spotify.com/api/token', querystring.stringify({
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: REDIRECT_URI, // Keep REDIRECT_URI dynamic on frontend
            client_id: SPOTIFY_CLIENT_ID,
            client_secret: SPOTIFY_CLIENT_SECRET
        }), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        const { access_token, refresh_token, expires_in } = tokenResponse.data;

        await admin.firestore().collection('users').doc(uid).set({
            spotifyAccessToken: access_token,
            spotifyRefreshToken: refresh_token,
            spotifyTokenExpiry: Date.now() + (expires_in * 1000),
            spotifyConnected: true
        }, { merge: true });

        // ✅ Dynamic frontend URL based on env
        const frontendURL = env === 'dev'
            ? 'http://localhost:5173'
            : process.env.FRONTEND_URL || 'https://airwavve.com';

        res.redirect(`${frontendURL}/spotify-auth-success?status=success&uid=${uid}`);
    } catch (error) {
        console.error('Error exchanging code for token:', error);

        const frontendURL = env === 'dev'
            ? 'http://localhost:5173'
            : process.env.FRONTEND_URL || 'https://airwavve.com';

        res.redirect(`${frontendURL}/spotify-auth-success?status=error&message=${encodeURIComponent(error?.message || 'Error during Spotify authentication')}`);
    }
});

exports.generateDJSegment = functions.https.onCall(async (data, context) => {
    // Set CORS headers
    const headers = {
        'Access-Control-Allow-Origin': '*', // Or specify your domain
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    if (context.rawRequest.method === 'OPTIONS') {
        return { headers, body: 'OK' };
    }

    console.log("DJ Segment - OpenAI call STARTED");

    const { userInput, prompt, maxLength } = data;

    if (!userInput) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing userInput');
    }

    let systemPrompt = `
You are a DJ host. Generate a spoken radio segment based on the user's input.

Keep it casual and sound like you are speaking naturally to an audience.
Don't include stage directions, sound effects, or anything outside normal speech.

The generated segment should be approximately ${maxLength} characters long. Return ONLY the text to be spoken.

User input:
`;

    if (prompt) {
        systemPrompt = prompt.replace(/\{\{maxLength\}\}/g, maxLength); // Allow maxLength in custom prompt
    } else {
        systemPrompt = systemPrompt.replace(/\{\{maxLength\}\}/g, maxLength);
    }

    const requestPayload = {
        model: "gpt-4o-mini",
        max_tokens: 4096, // Keep a reasonable limit
        temperature: 0.7,
        messages: [
            { role: "system", content: systemPrompt },
            { role: "user", content: userInput }
        ]
    };

    console.log('Request payload:', JSON.stringify(requestPayload, null, 2));

    try {
        const response = await axios.post('https://api.openai.com/v1/chat/completions', requestPayload, {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${openaiApiKey}`
            }
        });

        let openAIResponse = response.data.choices[0].message.content.trim();

        // Basic fallback to truncate if the AI doesn't respect the length perfectly
        if (openAIResponse.length > maxLength * 1.2) { // Allow a small buffer
            openAIResponse = openAIResponse.substring(0, Math.floor(maxLength * 1.2)) + "...";
            console.warn(`AI response exceeded target length significantly, truncated to ${openAIResponse.length} characters.`);
        }

        const tokenUsage = {
            promptTokens: response.data.usage.prompt_tokens,
            completionTokens: response.data.usage.completion_tokens,
            totalTokens: response.data.usage.total_tokens
        };

        return { headers, result: openAIResponse, tokenUsage: tokenUsage };
    } catch (error) {
        console.error('Error calling OpenAI API:', error.response ? error.response.data : error);
        throw new functions.https.HttpsError('internal', 'Error processing OpenAI request: ' + JSON.stringify(error.response ? error.response.data : error.message));
    }
});