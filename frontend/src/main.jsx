import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import './index.css'
import App from './App.jsx'
import axios from 'axios'

// ── API Authentication Interceptor ──────────────────────────────────
let apiToken = null;
let tokenPromise = null;   // Promise that resolves once token is fetched

const ensureToken = async () => {
    if (!apiToken) {
        if (!tokenPromise) {
            console.log("[Auth] Fetching API token...");
            // Only one fetch attempt in progress at a time
            tokenPromise = axios.get('/api/auth/token').then(res => {
                apiToken = res.data.token;
                console.log("[Auth] API token retrieved successfully.");
                tokenPromise = null;
            }).catch(err => {
                console.error("[Auth] Failed to fetch API token:", err);
                tokenPromise = null;
                throw err;
            });
        }
        await tokenPromise;
    }
};

axios.interceptors.request.use(async (config) => {
    // Skip token check for the auth endpoint itself or non-API routes
    if (config.url === '/api/auth/token' || !config.url.startsWith('/api')) {
        return config;
    }

    await ensureToken();

    if (apiToken) {
        config.headers['X-API-Token'] = apiToken;
    }
    return config;
}, (error) => {
    return Promise.reject(error);
});


createRoot(document.getElementById('root')).render(
    <StrictMode>
        <BrowserRouter>
            <App />
        </BrowserRouter>
    </StrictMode>,
)
