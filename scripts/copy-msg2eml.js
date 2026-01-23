import { copyFileSync, mkdirSync } from 'fs';
import { dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

try {
  mkdirSync('public/libs', { recursive: true });
  copyFileSync(
    'node_modules/msg2eml/lib/dist/msg2eml.bundle.js',
    'public/libs/msg2eml.bundle.js'
  );
  console.log('✓ Copied msg2eml.bundle.js to public/libs/');
} catch (err) {
  console.error('Failed to copy msg2eml library:', err.message);
  process.exit(1);
}
