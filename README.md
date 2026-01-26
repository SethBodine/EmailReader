# Email Header Analyzer & EML/MSG Parser

A production-grade web application for analyzing email headers and parsing EML/MSG files with user-friendly security guidance.

## Features

### 1. Header Analyzer
- Email authentication analysis (SPF, DKIM, DMARC, ARC)
- Spam score detection with explanations
- Email routing visualization
- Overall trustworthiness assessment
- Plain-language guidance (Good/Warning/Bad)

### 2. EML File Reader
- Parse .eml files (cross-platform email format)
- Extract attachments
- View complete headers
- Display HTML and plain text content
- Auto-populate header analyzer

### 3. MSG File Reader (NEW!)
- Parse .msg files (Outlook format)
- Full Mac compatibility (Outlook for Mac can't open .msg files)
- Extract attachments
- View complete headers
- Display email content
- Auto-populate header analyzer

## Technologies

- **React 18** + **Vite** - Modern build tooling
- **Tailwind CSS** (CDN) - Styling
- **postal-mime** - EML parsing (NPM package)
- **@kenjiuno/msgreader** - MSG parsing (NPM package)
- **Lucide React** - Icons

## Development

### Prerequisites
- Node.js 18+ and npm

### Installation

```bash
# Clone the repository
git clone https://github.com/SethBodine/EmailReader.git
cd EmailReader

# Install dependencies
npm install

# Start development server
npm run dev
```

Visit http://localhost:5173

### Build for Production

```bash
npm run build
```

Output will be in the `dist/` directory.

## Deployment to Cloudflare Pages

### Via Git Integration (Recommended)
1. Push your code to GitHub
2. Go to Cloudflare Pages dashboard
3. Connect your GitHub repository
4. Set build settings:
   - **Build command:** `npm run build`
   - **Build output directory:** `dist`
   - **Node version:** 18 or higher

### Via Direct Upload
```bash
npm run build
# Upload the 'dist' folder to Cloudflare Pages
```

## How It Works

### Privacy & Security
- **All processing happens locally in your browser**
- No files are uploaded to any server
- Email data never leaves your device
- Libraries bundled with the application

### Supported File Types
- **.eml** - Standard MIME email format (works everywhere)
- **.msg** - Microsoft Outlook format (now works on Mac!)

## Usage

### Analyzing Headers
1. Click "Header Analyzer" tab
2. Paste email headers (View > Message > Show Original in Gmail)
3. Click "Analyze Headers"
4. Review SPF, DKIM, DMARC, ARC status and spam indicators

### Reading Email Files
1. Click "EML/MSG Reader" tab
2. Upload an .eml or .msg file
3. View email content, attachments, and headers
4. Headers are automatically populated in the analyzer tab

## Project Structure

```
EmailReader/
 src/
    App.jsx           # Main application component
    main.jsx          # React entry point
    index.css         # Global styles
 index.html            # HTML template with CDN scripts
 package.json          # Dependencies and scripts
 vite.config.js        # Vite configuration
 .gitignore            # Git ignore rules
 README.md             # This file
```

## Browser Compatibility

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
- Modern mobile browsers

## Contributing

Issues and pull requests are welcome! Please ensure:
- Code follows existing style
- All features work in modern browsers
- Privacy/security principles are maintained

## License

MIT License - See LICENSE file for details

## Acknowledgments

- [postal-mime](https://github.com/postalsys/postal-mime) - Excellent EML parser
- [MSGReader](https://github.com/kenjiuno/MSGReader.js) - MSG file support
- [Tailwind CSS](https://tailwindcss.com/) - Utility-first CSS
- [Lucide](https://lucide.dev/) - Beautiful icons

## Support

For issues or questions:
- Open a GitHub issue
- Check existing issues for solutions
- Review the documentation

---

**Live Demo:** [eml.insecure.co.nz](https://eml.insecure.co.nz)

