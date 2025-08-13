# Weather Forecast Function Setup

This guide explains how to set up the weather forecast cloud function that generates AI-powered weather reports with text-to-speech.

## Prerequisites

1. **Google Maps API Key** - For geocoding (converting city names to coordinates)
2. **OpenWeatherMap API Key** - For weather data (free tier available)

## Setup Instructions

### 1. Get Google Maps API Key

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the **Geocoding API**:
   - Go to "APIs & Services" > "Library"
   - Search for "Geocoding API"
   - Click "Enable"
4. Create credentials:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "API Key"
   - Copy the API key

### 2. Get OpenWeatherMap API Key

1. Go to [OpenWeatherMap](https://openweathermap.org/api)
2. Sign up for a free account
3. Go to "My API Keys" in your account
4. Copy your API key

### 3. Configure Firebase Functions

Set the API keys in your Firebase Functions configuration:

```bash
# Set Google API key (used for both geocoding and weather)
firebase functions:config:set google.api_key="YOUR_GOOGLE_API_KEY"

# Verify the configuration
firebase functions:config:get
```

### 4. Deploy the Functions

```bash
# Deploy only the functions
firebase deploy --only functions
```

## How It Works

The `getWeatherForecast` function performs the following steps:

1. **Geocoding**: Converts the city name to latitude/longitude using Google Maps API
2. **Weather Data**: Fetches current weather conditions using OpenWeatherMap API
3. **AI Processing**: Uses OpenAI to generate a natural, conversational weather forecast (~250 words)
4. **Text-to-Speech**: Converts the forecast to audio using ElevenLabs TTS
5. **Token Management**: Deducts tokens from the user's account based on usage

## API Response Format

The function returns:

```json
{
  "success": true,
  "audioBase64": "base64_encoded_audio_data",
  "sampleRate": 22050,
  "forecastText": "The generated weather forecast text...",
  "weatherData": {
    "current": {
      "temp": 72,
      "feels_like": 74,
      "humidity": 65,
      "windSpeed": 8,
      "conditions": "partly cloudy",
      "pressure": 1013
    },
    "location": {
      "sunrise": "6:30:00 AM",
      "sunset": "7:45:00 PM"
    }
  }
}
```

## Frontend Integration

The frontend component (`AddWeatherForm.tsx`) has been updated to:

1. Accept a location input from the user
2. Call the `getWeatherForecast` cloud function
3. Convert the returned base64 audio to a playable blob URL
4. Display the weather data and generated forecast

## Error Handling

The function includes comprehensive error handling for:

- Invalid locations
- API rate limits
- Insufficient user tokens
- Network failures
- Invalid API responses

## Cost Considerations

- **Google Maps API**: $5 per 1000 geocoding requests
- **OpenWeatherMap**: Free tier includes 1000 calls/day
- **OpenAI**: ~$0.0015 per 1K tokens
- **ElevenLabs**: Varies by voice and usage

## Testing

To test the function:

1. Deploy the functions
2. Open the frontend application
3. Navigate to the weather forecast section
4. Enter a city name and select a voice
5. Click "Generate Weather Forecast"

The function will create a natural-sounding weather report with current conditions and forecasts.
