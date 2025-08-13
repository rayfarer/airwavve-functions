const functions = require('firebase-functions');
const admin = require('firebase-admin');
const Stripe = require('stripe');

const { onCall } = require('firebase-functions/v2/https');
const { defineString } = require('firebase-functions/params');
const fetch = require('node-fetch');
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

// Make sure you set this in functions config:
// firebase functions:config:set google.api_key="your_google_api_key_here"
const googleApiKey = functions.config().google.api_key;

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
        const addedTokens = 10000;


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



exports.getAllElevenlabsVoices = functions.https.onCall(async (data, context) => {
    if (!context.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'User must be authenticated.');
    }

    // Optional: blacklist voice IDs you don't want to show
    const blacklist = [
        "6AKHxakv0gUvEwsGQuHh"
    ];

    try {
        const response = await axios.get("https://api.elevenlabs.io/v1/voices", {
            headers: {
                "xi-api-key": elevenLabsApiKey
            }
        });

        const voices = response.data.voices
            .filter((voice) => !blacklist.includes(voice.voice_id))
            .map((voice) => ({
                id: voice.voice_id,
                name: voice.name,
                description: voice.description || '',
                previewUrl: voice.preview_url || null,
                labels: voice.labels || {}
            }));

        return { voices };
    } catch (err) {
        console.error("❌ Failed to fetch voices from ElevenLabs v2:", err?.response?.data || err.message);
        throw new functions.https.HttpsError("internal", "Failed to retrieve voice list.");
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
    const { userInput, prompt, maxLength = 300 } = data;
  
    if (!userInput) {
      throw new functions.https.HttpsError('invalid-argument', 'Missing userInput');
    }
  
    // Convert char target → token cap (+buffer), with bounds
    const approxTokens = Math.ceil(Number(maxLength) / 4);      // 4 chars ≈ 1 token
    const maxOut = Math.min(Math.max(approxTokens + 60, 80), 1200); // pad + clamp
  
    const baseSystem = `
  You are a DJ host. Generate a spoken radio segment based on the user's input.
  Keep it casual and natural—no stage directions or SFX.
  Aim for about ${Math.round(maxLength/6)}–${Math.round(maxLength/5)} words.
  It's okay to go a little longer to finish your last sentence cleanly.
  End on a complete sentence.
    `.trim();
  
    const systemPrompt = prompt
      ? prompt.replace(/\{\{maxLength\}\}/g, String(maxLength)) + "\n\nEnd on a complete sentence."
      : baseSystem;
  
    const requestPayload = {
      model: "gpt-4o-mini",
      temperature: 0.7,
      max_tokens: maxOut,                                // <-- cap by tokens, not chars
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userInput }
      ]
    };
  
    try {
      const response = await axios.post('https://api.openai.com/v1/chat/completions', requestPayload, {
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${openaiApiKey}` }
      });
  
      let text = (response.data.choices?.[0]?.message?.content || "").trim();
  
      // OPTIONAL: if it's significantly too long, trim to the last sentence boundary near the target
      const hardCap = Math.floor(maxLength * 1.35); // allow +35% to finish cleanly
      if (text.length > hardCap) {
        const slice = text.slice(0, hardCap);
        const lastStop = Math.max(slice.lastIndexOf("."), slice.lastIndexOf("!"), slice.lastIndexOf("?"));
        text = lastStop > 0 ? slice.slice(0, lastStop + 1) : slice + "…";
      }
  
      return {
        result: text,
        usedMaxTokens: maxOut,
        usage: response.data.usage
      };
    } catch (err) {
      console.error('Error calling OpenAI API:', err.response ? err.response.data : err);
      throw new functions.https.HttpsError('internal', 'Error processing OpenAI request');
    }
  });
  

async function getSpotifyToken(uid) {
    const userDoc = await admin.firestore().collection('users').doc(uid).get();
    if (!userDoc.exists) throw new Error('User not found');

    const refreshToken = userDoc.data().spotifyRefreshToken;
    if (!refreshToken) throw new Error('Missing Spotify refresh token');

    const tokenRes = await axios.post('https://accounts.spotify.com/api/token',
        querystring.stringify({
            grant_type: 'refresh_token',
            refresh_token: refreshToken,
            client_id: SPOTIFY_CLIENT_ID,
            client_secret: SPOTIFY_CLIENT_SECRET
        }),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const accessToken = tokenRes.data.access_token;
    await admin.firestore().collection('users').doc(uid).update({
        spotifyAccessToken: accessToken,
        spotifyTokenExpiry: Date.now() + tokenRes.data.expires_in * 1000
    });

    return accessToken;
}


exports.getSpotifyPlaylist = functions.https.onRequest(async (req, res) => {
    // ✅ Add CORS headers
    res.set('Access-Control-Allow-Origin', '*'); // Replace '*' with your frontend origin if needed
    res.set('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.set('Access-Control-Allow-Headers', 'Content-Type');

    // ✅ Handle preflight requests
    if (req.method === 'OPTIONS') {
        return res.status(204).send('');
    }

    const playlistUrl = req.query.url;
    const uid = req.query.uid;

    if (!playlistUrl) return res.status(400).json({ error: 'Missing playlist URL' });
    if (!uid) return res.status(400).json({ error: 'Missing UID' });

    const match = playlistUrl.match(/playlist\/([a-zA-Z0-9]+)/);
    if (!match) return res.status(400).json({ error: 'Invalid playlist URL' });

    const playlistId = match[1];

    let playlistName = '';

    try {
        const token = await getSpotifyToken(uid);

        // Fetch playlist metadata (for the name)
        const metaRes = await fetch(`https://api.spotify.com/v1/playlists/${playlistId}`, {
            headers: { Authorization: `Bearer ${token}` }
        });

        if (!metaRes.ok) throw new Error('Failed to fetch playlist metadata');
        const metaData = await metaRes.json();
        playlistName = metaData.name;

        // Then fetch tracks
        const tracks = [];
        let next = `https://api.spotify.com/v1/playlists/${playlistId}/tracks?limit=50`;

        while (next) {
            const response = await fetch(next, {
                headers: { Authorization: `Bearer ${token}` }
            });

            if (!response.ok) throw new Error('Failed to fetch playlist tracks');

            const data = await response.json();
            for (const item of data.items) {
                const t = item.track;
                if (t && t.id && t.uri) {
                    tracks.push({
                        id: t.id,
                        name: t.name,
                        uri: t.uri,
                        duration_ms: t.duration_ms,
                        artists: t.artists.map((a) => ({ name: a.name })),
                        album: {
                            name: t.album.name,
                            images: t.album.images
                        }
                    });
                }
            }
            next = data.next;
        }

        return res.status(200).json({ tracks, name: playlistName });
    } catch (err) {
        console.error('[getSpotifyPlaylist] Error:', err);
        return res.status(500).json({ error: 'Failed to fetch playlist' });
    }
});

exports.refreshSpotifyToken = functions.https.onCall(async (data, context) => {
    const { refreshToken } = data;

    console.log('🔍 Parsed data:', data);

    if (!refreshToken) {
        console.error('❌ No refreshToken provided');
        throw new functions.https.HttpsError('invalid-argument', 'Missing refreshToken');
    }

    const creds = Buffer.from(`${SPOTIFY_CLIENT_ID}:${SPOTIFY_CLIENT_SECRET}`).toString('base64');

    try {
        const tokenRes = await fetch('https://accounts.spotify.com/api/token', {
            method: 'POST',
            headers: {
                Authorization: `Basic ${creds}`,
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                grant_type: 'refresh_token',
                refresh_token: refreshToken,
            }),
        });

        const data = await tokenRes.json();

        if (!tokenRes.ok) {
            console.error('❌ Spotify responded with error:', data);
            throw new functions.https.HttpsError('internal', 'Spotify token refresh failed', data);
        }

        console.log('✅ Token refreshed successfully:', data);
        return data; // contains access_token, expires_in, etc.
    } catch (err) {
        console.error('❌ Unexpected error refreshing token:', err);
        throw new functions.https.HttpsError('internal', 'Internal server error');
    }
});


exports.recommendSongs = functions.https.onCall(async (payload, context) => {
    if (!context.auth) {
      throw new functions.https.HttpsError('unauthenticated', 'User must be authenticated');
    }
  
    try {
      const {
        existingSongs = [],
        showInfo = null,
        userContext = '',
        numberOfRecommendations = 5,
        includeCustomContent = false,
        creativityLevel = 'balanced',
      } = payload || {};
  
      const openaiApiKey = functions.config().openai.key;
      if (!openaiApiKey) {
        throw new functions.https.HttpsError('failed-precondition', 'Missing OpenAI API key config (openai.key).');
      }
  
      // Clamp counts / tokens
      const recCount = Math.min(Math.max(parseInt(numberOfRecommendations, 10) || 5, 1), 20);
      const maxOut = 1200; // token cap for the JSON answer
  
      // Build user prompt
      let userInput = `You are a music expert helping to recommend songs for a radio show.`;
  
      if (showInfo) {
        userInput += `
  
  Show Information:
    - Name: ${showInfo.name}
    - Description: ${showInfo.description}`;
      }
  
      if (Array.isArray(existingSongs) && existingSongs.length > 0) {
        const list = existingSongs
          .slice(0, 20) // keep prompt small
          .map(s => `- ${s.title}${s.artists ? ` by ${s.artists.join(', ')}` : ''}`)
          .join('\n');
  
        userInput += `
  
  Existing songs in the show:
  ${list}`;
      }
  
      if (userContext) {
        userInput += `
  
  Additional context from user: ${userContext}`;
      }
  
      // Creativity guidance (kept lightweight)
      let creativityInstructions = '';
      switch (creativityLevel) {
        case 'conservative':
          creativityInstructions = `
  RECOMMENDATION STYLE: Conservative - Focus on well-known, accessible tracks`;
          break;
        case 'adventurous':
          creativityInstructions = `
  RECOMMENDATION STYLE: Adventurous - Deep cuts and hidden gems`;
          break;
        case 'experimental':
          creativityInstructions = `
  RECOMMENDATION STYLE: Experimental - Obscure and boundary-pushing`;
          break;
        case 'balanced':
        default:
          creativityInstructions = `
  RECOMMENDATION STYLE: Balanced - Mix of popular and deeper cuts`;
          break;
      }
  
      userInput += `
  
  Based on the show's theme and existing songs, recommend ${recCount} songs that would fit well in this radio show.
  ${creativityInstructions}
  
  IMPORTANT: Consider full catalogs (album cuts, B-sides, live/demo versions) where appropriate.`;
      
      // Clarify what djPrompts should be (context-only, not song-specific)
      if (includeCustomContent) {
        userInput += `
  
  For the field "djPrompts":
  - Generate 1–3 brief, standalone prompts (one sentence each)
  - Prompts MUST focus on the user context and/or show theme only
  - Do NOT mention specific song titles, specific artists, or album names unless they appear in the user context text itself
  - Do NOT reference transitions, "next", "previous", or what's "coming up"
  - Each prompt should be usable at any point during the segment, independent of the song order
  
  Examples of GOOD prompts:
  - "Ozzy Osbourne passed away today—reflect on his influence on heavy music and cultural impact."
  - "Share a quick insight on how the British Invasion reshaped global rock culture."
  - "Invite listeners to share memories tied to classic British rock icons."
  
  Examples of BAD prompts (do not do this):
  - "Up next, this Beatles track…" (mentions a transition and a specific band)
  - "After Pink Floyd, we’ll…" (references song order/artists)
  - "Introduce 'Revolution 9'…" (mentions a specific song title)`;
      }
  
      // Light personality
      const personalities = [
        "You are a music expert specializing in radio programming. Always respond with valid JSON.",
        "You are a passionate music curator with eclectic tastes. Always respond with valid JSON.",
        "You are a music historian with deep catalog knowledge. Always respond with valid JSON.",
        "You are a tastemaker who balances discovery and familiarity. Always respond with valid JSON.",
      ];
      const systemPrompt = personalities[Math.floor(Math.random() * personalities.length)];
  
      // JSON schema(s)
      const songItemSchema = {
        type: "object",
        properties: {
          title: { type: "string" },
          artist: { type: "string" }
        },
        required: ["title", "artist"],
        additionalProperties: false
      };
  
      // Structured output via text.format
      const textFormat = includeCustomContent
        ? {
            type: "json_schema",
            name: "recommendations_with_prompts",
            strict: true,
            schema: {
              type: "object",
              properties: {
                songs: {
                  type: "array",
                  items: songItemSchema,
                  minItems: recCount,
                  maxItems: recCount
                },
                djPrompts: {
                  type: "array",
                  items: { type: "string" },
                  minItems: 1,
                  maxItems: 3
                }
              },
              required: ["songs", "djPrompts"],
              additionalProperties: false
            }
          }
        : {
            type: "json_schema",
            name: "song_list",
            strict: true,
            schema: {
              type: "array",
              items: songItemSchema,
              minItems: recCount,
              maxItems: recCount
            }
          };
  
      // Build Responses API payload (NOTE: content[].type = "input_text")
      const requestPayload = {
        model: "gpt-5-mini",
        max_output_tokens: 1500,             // include headroom for any residual reasoning
        reasoning: { effort: "low" },        // minimize reasoning tokens
        text: { format: textFormat },
        input: [
          { role: "system", content: [{ type: "input_text", text: systemPrompt + "\nOnly output the JSON. No explanations." }] },
          { role: "user",   content: [{ type: "input_text", text: userInput }] }
        ]
      };

      function extractOutputText(resp) {
        if (resp?.output_text) return String(resp.output_text);
      
        // Find the assistant message
        const msg = resp?.output?.find?.(o => o?.type === "message" && Array.isArray(o.content));
        if (!msg) return "";
      
        // Collect all output_text chunks (there can be more than one)
        const chunks = msg.content
          .filter(c => c?.type === "output_text" && typeof c.text === "string")
          .map(c => c.text);
      
        return chunks.join("").trim();
      }
  
      // Call OpenAI
      const openaiResp = (await axios.post("https://api.openai.com/v1/responses", requestPayload, {
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${openaiApiKey}`
        },
        timeout: 45000
      })).data;
  
      // Aggregated text (JSON string due to text.format)
      const text = extractOutputText(openaiResp);
        if (!text) {
        console.error("Empty output_text shape:", JSON.stringify(openaiResp, null, 2));
        throw new functions.https.HttpsError('internal', 'Empty model response');
        }

        let parsed;
        try {
        parsed = JSON.parse(text);
        } catch (e) {
        console.error("JSON parse failed. Raw text:", text);
        throw new functions.https.HttpsError('internal', 'Failed to parse AI JSON');
        }
  
      // Normalize & validate
      if (includeCustomContent) {
        if (!parsed?.songs || !Array.isArray(parsed.songs)) {
          throw new functions.https.HttpsError('internal', 'AI response missing songs array');
        }
  
        const validatedSongs = parsed.songs.map((s, i) => {
          if (!s?.title || !s?.artist) {
            throw new functions.https.HttpsError('internal', `Invalid song at index ${i}`);
          }
          return { title: s.title, artist: s.artist };
        });
  
        const djPrompts = Array.isArray(parsed.djPrompts) && parsed.djPrompts.length
          ? parsed.djPrompts.slice(0, 3)
          : (userContext
              ? [`${userContext}. Share some thoughts about this music.`]
              : ["Introduce the segment, set the mood, and preview what’s next."]);
  
        return {
          recommendedSongs: validatedSongs,
          customContent: { djPrompts },
          usedMaxTokens: maxOut,
          usage: openaiResp.usage
        };
      } else {
        if (!Array.isArray(parsed)) {
          throw new functions.https.HttpsError('internal', 'Expected an array of songs');
        }
  
        const validatedSongs = parsed.map((s, i) => {
          if (!s?.title || !s?.artist) {
            throw new functions.https.HttpsError('internal', `Invalid song at index ${i}`);
          }
          return { title: s.title, artist: s.artist };
        });
  
        return {
          recommendedSongs: validatedSongs,
          usedMaxTokens: maxOut,
          usage: openaiResp.usage
        };
      }
    } catch (err) {
      const details = err?.response?.data || err?.message || err;
      console.error('Error in recommendSongs:', JSON.stringify(details, null, 2));
      if (err instanceof functions.https.HttpsError) throw err;
      throw new functions.https.HttpsError('internal', 'Failed to generate song recommendations');
    }
  });


exports.getWeatherForecast = functions.https.onCall(async (data, context) => {
    if (!context.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'User must be authenticated.');
    }

    const { uid } = context.auth;
    const { location, voiceId, unitsSystem = 'IMPERIAL', forecastLength = 'NORMAL', showInfo = null } = data;
    
    if (!location || !voiceId) {
        throw new functions.https.HttpsError('invalid-argument', 'Must provide location and voiceId.');
    }

    // Validate units system
    if (!['IMPERIAL', 'METRIC'].includes(unitsSystem)) {
        throw new functions.https.HttpsError('invalid-argument', 'unitsSystem must be either IMPERIAL or METRIC.');
    }

    // Validate forecast length
    if (!['BRIEF', 'NORMAL', 'LONG'].includes(forecastLength)) {
        throw new functions.https.HttpsError('invalid-argument', 'forecastLength must be either BRIEF, NORMAL, or LONG.');
    }

    // Check user tokens first
    const userRef = admin.firestore().collection('users').doc(uid);
    const userDoc = await userRef.get();
    if (!userDoc.exists) {
        throw new functions.https.HttpsError('not-found', 'User not found.');
    }

    const userTokens = userDoc.data().tokens || 0;
    
    // Map forecast length to estimated token cost and descriptions
    const forecastLengthConfig = {
        'BRIEF': { maxTokens: 50, estimatedCost: 150, description: 'current conditions only - just a quick update on what it\'s like right now' },
        'NORMAL': { maxTokens: 200, estimatedCost: 350, description: 'a paragraph with current conditions, today\'s high/low, wind, and tonight\'s forecast' },
        'LONG': { maxTokens: 500, estimatedCost: 700, description: 'a comprehensive forecast including the 5-day outlook' }
    };
    
    const config = forecastLengthConfig[forecastLength];
    const estimatedTokens = config.estimatedCost; // Weather API call + OpenAI processing + TTS generation
    
    if (userTokens < estimatedTokens) {
        throw new functions.https.HttpsError(
            'out-of-range',
            'Insufficient tokens.',
            { userTokens, requiredTokens: estimatedTokens }
        );
    }

    try {
        // Step 1: Get weather data from Google Weather API
        const weatherResponse = await axios.get(
            `https://maps.googleapis.com/maps/api/geocode/json?address=${encodeURIComponent(location)}&key=${googleApiKey}`
        );

        if (!weatherResponse.data.results || weatherResponse.data.results.length === 0) {
            throw new functions.https.HttpsError('internal', 'Location not found.');
        }

        const locationData = weatherResponse.data.results[0].geometry.location;
        const lat = locationData.lat;
        const lng = locationData.lng;

        // Get weather data using Google Weather API v1 daily forecast
        const weatherDataResponse = await axios.get(
            `https://weather.googleapis.com/v1/forecast/days:lookup?key=${googleApiKey}&location.latitude=${lat}&location.longitude=${lng}&unitsSystem=${unitsSystem}&days=5`
        );

        if (!weatherDataResponse.data) {
            throw new functions.https.HttpsError('internal', 'Failed to fetch weather data.');
        }

        const weatherData = weatherDataResponse.data;
        const forecastDays = weatherData.forecastDays || [];
        const today = forecastDays[0] || {};
        const nextDays = forecastDays.slice(1, 5) || []; // Next 4 days

        // Step 2: Generate forecast description using OpenAI
        const tempUnit = unitsSystem === 'METRIC' ? 'C' : 'F';
        const windUnit = unitsSystem === 'METRIC' ? 'km/h' : 'mph';
        
        // Use the config that was already defined above
        const config = forecastLengthConfig[forecastLength];
        
        // Build show context if available
        let showContext = '';
        if (showInfo && showInfo.name && showInfo.description) {
            showContext = `
Show Context:
- Show Name: ${showInfo.name}
- Show Description: ${showInfo.description}

Please incorporate the show's theme and style into your weather report. Make it feel like it belongs in this specific radio show.`;
        }
        
        const weatherPrompt = `
Generate a natural, conversational weather forecast for ${location} based on the following data:${showContext}

Today's Forecast:
- High: ${today.maxTemperature?.degrees || 'N/A'}°${tempUnit}
- Low: ${today.minTemperature?.degrees || 'N/A'}°${tempUnit}
- Feels like high: ${today.feelsLikeMaxTemperature?.degrees || 'N/A'}°${tempUnit}
- Feels like low: ${today.feelsLikeMinTemperature?.degrees || 'N/A'}°${tempUnit}
- Daytime conditions: ${today.daytimeForecast?.weatherCondition?.description?.text || 'N/A'}
- Nighttime conditions: ${today.nighttimeForecast?.weatherCondition?.description?.text || 'N/A'}
- Precipitation chance: ${today.daytimeForecast?.precipitation?.probability?.percent || 'N/A'}%
- Wind: ${today.daytimeForecast?.wind?.speed?.value || 'N/A'} ${windUnit}
- Humidity: ${today.daytimeForecast?.relativeHumidity || 'N/A'}%
- Sunrise: ${today.sunEvents?.sunriseTime ? new Date(today.sunEvents.sunriseTime).toLocaleTimeString() : 'N/A'}
- Sunset: ${today.sunEvents?.sunsetTime ? new Date(today.sunEvents.sunsetTime).toLocaleTimeString() : 'N/A'}

5-Day Forecast:
${nextDays.map((day, i) => {
  const date = new Date(day.interval?.startTime);
  const dayName = date.toLocaleDateString('en-US', { weekday: 'long' });
  return `- ${dayName}: High ${day.maxTemperature?.degrees || 'N/A'}°${tempUnit}, Low ${day.minTemperature?.degrees || 'N/A'}°${tempUnit}, ${day.daytimeForecast?.weatherCondition?.description?.text || 'N/A'}, ${day.daytimeForecast?.precipitation?.probability?.percent || 'N/A'}% rain chance`;
}).join('\n')}

Write a friendly, informative weather report that's ${config.description}. Make it sound natural and conversational, like a radio weather report.${showInfo ? ' Tailor the tone and style to match the show\'s personality and theme.' : ''}

FORECAST LENGTH GUIDELINES:
- BRIEF: Focus ONLY on current conditions. Example: "It's 56 and sunny out there London, enjoy your day!"
- NORMAL: Include current conditions, today's high/low, wind, and tonight's forecast. Example: "It's 56 and sunny out there, with a high of 65 and a low of 45. There's no wind. Tonight it's going to be clear and cool."
- LONG: Include everything above plus the 5-day forecast outlook.

IMPORTANT TTS FORMATTING RULES:
- Round all temperatures to whole numbers (e.g., "around 14" instead of "14.7")
- Spell out "degrees" or omit it entirely (e.g., "14 degrees" or just "14")
- Avoid decimal points in temperature readings
- Spell out percentages (e.g., "around 14 percent" instead of "14%")
- Make the text sound natural when spoken aloud`;

        const openaiResponse = await axios.post('https://api.openai.com/v1/chat/completions', {
            model: "gpt-4o-mini",
            temperature: 0.7,
            max_tokens: config.maxTokens + 100, // Add buffer to ensure complete sentences
            messages: [
                { role: "system", content: "You are a friendly weather reporter. Write natural, conversational weather forecasts that are informative and engaging. Always round temperatures to whole numbers and spell out 'degrees' or omit it entirely for better TTS pronunciation. IMPORTANT: Always finish your response with a complete sentence - do not cut off mid-sentence." },
                { role: "user", content: weatherPrompt }
            ]
        }, {
            headers: { 
                'Content-Type': 'application/json', 
                'Authorization': `Bearer ${openaiApiKey}` 
            }
        });

        let forecastText = openaiResponse.data.choices?.[0]?.message?.content?.trim();
        if (!forecastText) {
            throw new functions.https.HttpsError('internal', 'Failed to generate weather forecast text.');
        }

        // Ensure the text ends with a complete sentence
        const sentenceEndings = ['.', '!', '?'];
        const lastChar = forecastText.slice(-1);
        
        if (!sentenceEndings.includes(lastChar)) {
            // Find the last complete sentence
            let lastSentenceEnd = -1;
            for (const ending of sentenceEndings) {
                const pos = forecastText.lastIndexOf(ending);
                if (pos > lastSentenceEnd) {
                    lastSentenceEnd = pos;
                }
            }
            
            if (lastSentenceEnd > 0) {
                forecastText = forecastText.substring(0, lastSentenceEnd + 1);
            }
        }

        // Step 3: Convert to speech using ElevenLabs
        const ttsResponse = await axios({
            method: 'post',
            url: `https://api.elevenlabs.io/v1/text-to-speech/${voiceId}`,
            headers: {
                'xi-api-key': elevenLabsApiKey,
                'Content-Type': 'application/json',
            },
            responseType: 'arraybuffer',
            data: {
                text: forecastText,
                model_id: 'eleven_multilingual_v2',
                voice_settings: { stability: 0.5, similarity_boost: 0.5 }
            }
        });

        const contentType = ttsResponse.headers['content-type'] || '';
        if (!contentType.startsWith('audio/')) {
            const errorText = Buffer.from(ttsResponse.data).toString('utf8');
            console.error('❌ ElevenLabs returned non-audio payload:', errorText);
            throw new functions.https.HttpsError(
                'internal',
                'ElevenLabs TTS did not return audio.'
            );
        }

        // Calculate actual token usage and deduct
        const actualTokens = Math.ceil(forecastText.length * 0.5);
        await userRef.update({
            tokens: admin.firestore.FieldValue.increment(-actualTokens)
        });

        const audioBuffer = ttsResponse.data;
        const base64Audio = Buffer.from(audioBuffer).toString('base64');

        return {
            success: true,
            audioBase64: base64Audio,
            sampleRate: 22050,
            forecastText: forecastText,
            weatherData: {
                unitsSystem: unitsSystem,
                today: {
                    high: today.maxTemperature?.degrees,
                    low: today.minTemperature?.degrees,
                    feelsLikeHigh: today.feelsLikeMaxTemperature?.degrees,
                    feelsLikeLow: today.feelsLikeMinTemperature?.degrees,
                    daytimeConditions: today.daytimeForecast?.weatherCondition?.description?.text,
                    nighttimeConditions: today.nighttimeForecast?.weatherCondition?.description?.text,
                    precipitationChance: today.daytimeForecast?.precipitation?.probability?.percent,
                    windSpeed: today.daytimeForecast?.wind?.speed?.value,
                    humidity: today.daytimeForecast?.relativeHumidity,
                    sunrise: today.sunEvents?.sunriseTime,
                    sunset: today.sunEvents?.sunsetTime
                },
                forecast: {
                    days: nextDays.map(day => {
                        const date = new Date(day.interval?.startTime);
                        return {
                            date: date.toISOString().split('T')[0],
                            dayName: date.toLocaleDateString('en-US', { weekday: 'long' }),
                            high: day.maxTemperature?.degrees,
                            low: day.minTemperature?.degrees,
                            conditions: day.daytimeForecast?.weatherCondition?.description?.text,
                            precipitationChance: day.daytimeForecast?.precipitation?.probability?.percent
                        };
                    })
                }
            }
        };

    } catch (err) {
        console.error('🔥 Error in getWeatherForecast:', err);
        if (err instanceof functions.https.HttpsError) {
            throw err;
        }
        throw new functions.https.HttpsError('internal', 'Failed to generate weather forecast.');
    }
});