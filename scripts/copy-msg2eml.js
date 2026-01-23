import { writeFileSync, mkdirSync } from 'fs';
import { dirname } from 'path';
import { fileURLToPath } from 'url';
import https from 'https';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Download msg2eml.bundle.js from GitHub
const url = 'https://raw.githubusercontent.com/master131/msg2eml.js/master/lib/dist/msg2eml.bundle.js';

try {
  mkdirSync('public/libs', { recursive: true });
  console.log('Downloading msg2eml.bundle.js...');
  
  https.get(url, (res) => {
    let data = '';
    
    res.on('data', (chunk) => {
      data += chunk;
    });
    
    res.on('end', () => {
      writeFileSync('public/libs/msg2eml.bundle.js', data);
      console.log('✓ Downloaded msg2eml.bundle.js to public/libs/');
    });
  }).on('error', (err) => {
    console.error('Failed to download msg2eml library:', err.message);
    process.exit(1);
  });
} catch (err) {
  console.error('Failed to create directory:', err.message);
  process.exit(1);
}
