#!/bin/bash
set -e

echo "Building msg2eml.js with proper bundling..."

# Navigate to msg2eml.js directory
cd msg2eml.js

# Clean previous builds
rm -rf node_modules lib

# Install dependencies
npm install

# Rebuild with browserify to properly bundle ALL dependencies
echo "Running custom browserify build to bundle all dependencies..."

# First compile TypeScript
npx tsc

# Then use browserify with --no-bundle-external false to bundle everything
npx browserify lib/msg2eml.js \
  --standalone msg2eml \
  -t [ babelify --presets [ @babel/preset-env ] ] \
  --no-builtins \
  --insert-global-vars="global" \
  -o lib/msg2eml.browserify.js

# Babel it
npx babel lib/msg2eml.browserify.js \
  -o lib/dist/msg2eml.bundle.js \
  --compact=false

# Verify the build succeeded
if [ ! -f "lib/dist/msg2eml.bundle.js" ]; then
  echo "ERROR: msg2eml.bundle.js was not created!"
  exit 1
fi

echo "Build complete. File size:"
ls -lh lib/dist/msg2eml.bundle.js

# Copy built files to public/libs
cd ..
mkdir -p public/libs
cp msg2eml.js/lib/dist/msg2eml.bundle.js public/libs/msg2eml.bundle.js

echo "✓ msg2eml.bundle.js built and copied to public/libs/"
echo "✓ All dependencies should be bundled"
