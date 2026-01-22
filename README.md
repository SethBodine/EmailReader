# Email Header Analyzer & EML/MSG Parser

A production-grade web application for analyzing email headers and parsing EML/MSG files with user-friendly security guidance.

## Features

### Header Decoder
- Email authentication analysis (SPF, DKIM, DMARC, ARC)
- Spam score detection with explanations
- Email routing visualization
- Overall trustworthiness assessment
- Plain-language guidance (Good/Warning/Bad)

### EML/MSG Converter
- Parse .eml and .msg files
- Outlook Mac compatibility (opens .msg files)
- Extract attachments
- View complete headers
- Display HTML and plain text content

## Technologies
- React 18 + Vite
- Tailwind CSS (CDN)
- postal-mime v2.7.3 (CDN)
- @kenjiuno/msgreader v1.27.1 (CDN)
- Lucide React icons

## Development

\`\`\`bash
npm install
npm run dev
\`\`\`

Visit http://localhost:5173

## Production Build

\`\`\`bash
npm run build
\`\`\`

Output: `dist/` directory

## Deployment

Optimized for Cloudflare Pages. See deployment guide for details.

## License

MIT
