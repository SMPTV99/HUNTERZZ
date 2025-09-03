const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
    origin: true,
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());

// Store for CSRF tokens (cookie -> {token, timestamp})
let csrfTokens = new Map();

// CSRF token management
function getStoredCSRFToken(robloxCookie) {
    const tokenData = csrfTokens.get(robloxCookie);
    if (!tokenData) return null;
    
    // Check if token is still valid (less than 5 minutes old)
    const now = Date.now();
    if (now - tokenData.timestamp < 5 * 60 * 1000) {
        return tokenData.token;
    }
    
    // Token expired, remove it
    csrfTokens.delete(robloxCookie);
    return null;
}

function storeCSRFToken(robloxCookie, token) {
    csrfTokens.set(robloxCookie, {
        token: token,
        timestamp: Date.now()
    });
}

// Enhanced CSRF token retrieval
async function getCSRFToken(robloxCookie) {
    console.log('🔑 Attempting to get CSRF token from Roblox...');
    
    // Try multiple endpoints that typically return CSRF tokens
    const endpoints = [
        {
            url: 'https://auth.roblox.com/v2/login',
            method: 'POST'
        },
        {
            url: 'https://www.roblox.com/home',
            method: 'GET'
        },
        {
            url: 'https://users.roblox.com/v1/users/authenticated',
            method: 'GET'
        },
        {
            url: 'https://itemconfiguration.roblox.com/v1/creations/get-asset-details',
            method: 'POST'
        }
    ];
    
    for (const endpoint of endpoints) {
        try {
            console.log(`Trying endpoint: ${endpoint.url}`);
            
            const requestOptions = {
                method: endpoint.method,
                headers: {
                    'Cookie': `.ROBLOSECURITY=${robloxCookie}`,
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'application/json',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Referer': 'https://www.roblox.com/',
                    'Origin': 'https://www.roblox.com'
                },
                redirect: 'manual'
            };
            
            const response = await fetch(endpoint.url, requestOptions);
            const csrfToken = response.headers.get('x-csrf-token');
            
            if (csrfToken) {
                console.log('✅ CSRF Token received successfully');
                storeCSRFToken(robloxCookie, csrfToken);
                return csrfToken;
            }
            
            // If we get a 403, it might indicate we need a CSRF token
            if (response.status === 403) {
                const wwwAuthenticate = response.headers.get('www-authenticate');
                if (wwwAuthenticate && wwwAuthenticate.includes('X-CSRF-TOKEN')) {
                    console.log('ℹ️  Endpoint requires CSRF token but none provided');
                    continue;
                }
            }
        } catch (error) {
            console.log(`Endpoint ${endpoint.url} failed:`, error.message);
            continue;
        }
    }
    
    console.error('❌ Could not obtain CSRF token from any endpoint');
    return null;
}

// Validate cookie by checking if it can authenticate
async function validateCookieWithRoblox(robloxCookie) {
    try {
        console.log('🔍 Validating cookie with Roblox...');
        
        // Get CSRF token first
        let csrfToken = getStoredCSRFToken(robloxCookie) || await getCSRFToken(robloxCookie);
        if (!csrfToken) {
            return {
                valid: false,
                error: 'Could not obtain CSRF token for validation'
            };
        }

        console.log('✅ Using CSRF token for validation');
        
        // Try to get current user info - this validates the cookie
        const response = await fetch('https://users.roblox.com/v1/users/authenticated', {
            headers: {
                'Cookie': `.ROBLOSECURITY=${robloxCookie}`,
                'X-CSRF-TOKEN': csrfToken,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'application/json',
                'Accept-Language': 'en-US,en;q=0.9',
                'Referer': 'https://www.roblox.com/',
                'Origin': 'https://www.roblox.com'
            }
        });

        console.log(`Validation response status: ${response.status}`);
        
        if (response.status === 401) {
            return {
                valid: false,
                error: 'Cookie is invalid or expired'
            };
        }
        
        if (response.status === 403) {
            // CSRF token might be invalid or expired
            const responseText = await response.text();
            if (responseText.includes('Token Validation Failed') || 
                responseText.includes('CSRF')) {
                
                console.log('🔄 CSRF token invalid or expired, requesting new one...');
                csrfToken = await getCSRFToken(robloxCookie);
                
                if (!csrfToken) {
                    return {
                        valid: false,
                        error: 'Could not obtain valid CSRF token'
                    };
                }

                // Retry with new token
                const retryResponse = await fetch('https://users.roblox.com/v1/users/authenticated', {
                    headers: {
                        'Cookie': `.ROBLOSECURITY=${robloxCookie}`,
                        'X-CSRF-TOKEN': csrfToken,
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                        'Accept': 'application/json',
                        'Accept-Language': 'en-US,en;q=0.9',
                        'Referer': 'https://www.roblox.com/',
                        'Origin': 'https://www.roblox.com'
                    }
                });

                if (!retryResponse.ok) {
                    return {
                        valid: false,
                        error: `Roblox API returned ${retryResponse.status} - Cookie may be invalid`
                    };
                }

                const userData = await retryResponse.json();
                return {
                    valid: true,
                    userId: userData.id,
                    username: userData.name,
                    displayName: userData.displayName
                };
            }
            
            // Other 403 error (not CSRF related)
            return {
                valid: false,
                error: `Access forbidden (403). Cookie may have insufficient permissions.`
            };
        }

        if (!response.ok) {
            return {
                valid: false,
                error: `Roblox API returned ${response.status}`
            };
        }

        const userData = await response.json();
        console.log(`✅ Validation successful for user: ${userData.name}`);
        return {
            valid: true,
            userId: userData.id,
            username: userData.name,
            displayName: userData.displayName
        };
    } catch (error) {
        console.error('Error validating cookie:', error.message);
        return {
            valid: false,
            error: error.message
        };
    }
}

// Refresh cookie by making a request to an endpoint that extends the session
async function refreshCookieWithRoblox(robloxCookie) {
    try {
        console.log('🔄 Attempting to refresh cookie session...');
        
        // Get CSRF token first
        let csrfToken = getStoredCSRFToken(robloxCookie);
        if (!csrfToken) {
            // Validate first to get a token
            const validation = await validateCookieWithRoblox(robloxCookie);
            if (!validation.valid) {
                return {
                    refreshed: false,
                    error: 'Cannot refresh invalid cookie: ' + validation.error
                };
            }
            csrfToken = getStoredCSRFToken(robloxCookie);
        }

        if (!csrfToken) {
            csrfToken = await getCSRFToken(robloxCookie);
            if (!csrfToken) {
                return {
                    refreshed: false,
                    error: 'Could not obtain CSRF token for refresh'
                };
            }
        }

        console.log('✅ Using CSRF token for refresh');
        
        // Try multiple endpoints that can refresh the session
        const endpoints = [
            {
                url: 'https://economy.roblox.com/v1/user/currency',
                method: 'GET',
                description: 'Economy endpoint'
            },
            {
                url: 'https://thumbnails.roblox.com/v1/users/avatar',
                method: 'GET',
                description: 'Avatar endpoint'
            },
            {
                url: 'https://catalog.roblox.com/v1/catalog/items/details',
                method: 'POST',
                body: JSON.stringify({ items: [{ id: 1, itemType: 'Asset' }] }),
                description: 'Catalog endpoint'
            }
        ];
        
        let lastResponse = null;
        
        for (const endpoint of endpoints) {
            try {
                console.log(`Trying refresh endpoint: ${endpoint.description}`);
                
                const requestOptions = {
                    method: endpoint.method,
                    headers: {
                        'Cookie': `.ROBLOSECURITY=${robloxCookie}`,
                        'X-CSRF-TOKEN': csrfToken,
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                        'Accept': 'application/json',
                        'Accept-Language': 'en-US,en;q=0.9',
                        'Referer': 'https://www.roblox.com/',
                        'Origin': 'https://www.roblox.com',
                        'Content-Type': 'application/json'
                    },
                    redirect: 'manual'
                };
                
                if (endpoint.body) {
                    requestOptions.body = endpoint.body;
                }
                
                const response = await fetch(endpoint.url, requestOptions);
                lastResponse = response;
                console.log(`Response from ${endpoint.description}: ${response.status}`);
                
                // If we get a successful response, the session is active
                if (response.status === 200 || response.status === 201 || response.status === 204) {
                    console.log('✅ Cookie session refreshed successfully');
                    return {
                        refreshed: true,
                        cookie: robloxCookie
                    };
                }
                
                // Handle CSRF token errors specifically
                if (response.status === 403) {
                    const responseText = await response.text();
                    if (responseText.includes('Token Validation Failed') || 
                        responseText.includes('CSRF')) {
                        
                        console.log('🔄 CSRF token invalid, getting new token...');
                        csrfToken = await getCSRFToken(robloxCookie);
                        
                        if (csrfToken) {
                            // Update the request with new token and retry
                            requestOptions.headers['X-CSRF-TOKEN'] = csrfToken;
                            const retryResponse = await fetch(endpoint.url, requestOptions);
                            
                            if (retryResponse.status === 200 || retryResponse.status === 201 || retryResponse.status === 204) {
                                console.log('✅ Cookie session refreshed with new CSRF token');
                                return {
                                    refreshed: true,
                                    cookie: robloxCookie
                                };
                            }
                        }
                        
                        // If we still can't get it to work after token refresh, continue to next endpoint
                        continue;
                    }
                }
                
                if (response.status === 401) {
                    // Cookie is definitely invalid/expired
                    console.log('❌ Cookie is invalid or expired');
                    return {
                        refreshed: false,
                        error: 'Cookie is invalid or expired'
                    };
                }
            } catch (error) {
                console.log(`Endpoint ${endpoint.description} failed:`, error.message);
                continue;
            }
        }
        
        // If we reached here but got some successful-looking responses, the cookie is likely valid
        if (lastResponse && (lastResponse.status === 403 || lastResponse.status === 401)) {
            console.log('❌ All endpoints failed with authentication errors');
            return {
                refreshed: false,
                error: 'Cookie could not be refreshed due to authentication errors'
            };
        }
        
        // If we reached here, the cookie might still be valid but we couldn't confirm via API
        console.log('⚠️  Could not confirm refresh but cookie may still be valid');
        return {
            refreshed: true,
            cookie: robloxCookie,
            warning: 'Refresh confirmation failed but cookie appears valid'
        };
    } catch (error) {
        console.error('Error refreshing cookie:', error.message);
        return {
            refreshed: false,
            error: error.message
        };
    }
}

// Routes
app.get('/api/status', (req, res) => {
    res.json({ 
        status: 'OK', 
        version: '2.1.0',
        message: 'Choblox Cookie Refresher API is running',
        timestamp: new Date().toISOString()
    });
});

app.post('/api/validate', async (req, res) => {
    try {
        const { cookie } = req.body;
        
        if (!cookie) {
            return res.status(400).json({ 
                valid: false, 
                error: 'No cookie provided' 
            });
        }
        
        // Validate the cookie with Roblox
        const validationResult = await validateCookieWithRoblox(cookie);
        res.json(validationResult);
    } catch (error) {
        console.error('Error in validate endpoint:', error);
        res.status(500).json({ 
            valid: false, 
            error: 'Internal server error' 
        });
    }
});

app.post('/api/refresh', async (req, res) => {
    try {
        const { cookie } = req.body;
        
        if (!cookie) {
            return res.status(400).json({ 
                refreshed: false, 
                error: 'No cookie provided' 
            });
        }
        
        // Refresh the cookie with Roblox
        const refreshResult = await refreshCookieWithRoblox(cookie);
        res.json(refreshResult);
    } catch (error) {
        console.error('Error in refresh endpoint:', error);
        res.status(500).json({ 
            refreshed: false, 
            error: 'Internal server error' 
        });
    }
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({ 
        error: 'Internal server error',
        message: error.message 
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Choblox Cookie Refresher API running on port ${PORT}`);
    console.log(`📍 Endpoint: http://localhost:${PORT}`);
    console.log(`📋 Make sure your ROBLOSECURITY cookie is valid and not expired`);
});