const axios = require('axios');
const cheerio = require('cheerio');
const express = require('express');

const app = express();
const PORT = 3000;

// Middleware to parse JSON bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Function to scan for vulnerabilities
async function scanWebsite(url) {
    try {
        const response = await axios.get(url);
        const $ = cheerio.load(response.data);

        const vulnerabilities = [];

        // Check for outdated libraries (example for jQuery)
        $('script[src]').each((index, element) => {
            const src = $(element).attr('src');
            if (src && src.includes('jquery')) {
                if (!src.includes('3.5.1')) { // Example version check
                    vulnerabilities.push("Potential outdated jQuery version found.");
                }
            }
        });

        // Check for missing security headers
        const headers = response.headers;
        if (!headers['x-content-type-options']) {
            vulnerabilities.push("Missing X-Content-Type-Options header.");
        }
        if (!headers['x-frame-options']) {
            vulnerabilities.push("Missing X-Frame-Options header.");
        }
        if (!headers['x-xss-protection']) {
            vulnerabilities.push("Missing X-XSS-Protection header.");
        }

        return vulnerabilities;

    } catch (error) {
        console.error(`Error accessing ${url}: ${error.message}`);
        return [`Error accessing ${url}: ${error.message}`];
    }
}

// Express route for scanning a website
app.post('/scan', async (req, res) => {
    const { url } = req.body;
    const vulnerabilities = await scanWebsite(url);
    res.json({ url, vulnerabilities });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Vulnerability Assessment Tool running on http://localhost:${PORT}`);
});
