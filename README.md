# Vulnerability Assessment Tool

## Overview

The **Vulnerability Assessment Tool** is a Node.js application designed to scan web applications for known vulnerabilities. This tool checks for outdated libraries, missing security headers, and other common vulnerabilities, providing a report that helps developers and security professionals enhance the security posture of their web applications.

## Features

- **Web Vulnerability Scanning**: Automatically scans specified URLs for potential vulnerabilities.
- **Outdated Library Detection**: Identifies outdated versions of commonly used libraries (e.g., jQuery).
- **Security Header Checks**: Verifies the presence of important HTTP security headers, such as:
  - `X-Content-Type-Options`
  - `X-Frame-Options`
  - `X-XSS-Protection`
- **RESTful API**: Provides a simple API endpoint for easy integration with other tools or services.

## Technologies Used

- **Node.js**: The runtime environment for executing JavaScript on the server side.
- **Express**: A web framework for building the RESTful API.
- **Axios**: For making HTTP requests to fetch web pages.
- **Cheerio**: For parsing and querying HTML content.
