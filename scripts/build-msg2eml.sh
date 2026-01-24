#!/bin/bash
set -e

echo "Building msg2eml.js..."

# Navigate to msg2eml.js directory
cd msg2eml.js

# Install dependencies
npm install

# Build the library
npm run build

# Copy built files to public/libs
cd ..
mkdir -p public/libs
cp msg2eml.js/lib/dist/msg2eml.bundle.js public/libs/msg2eml.bundle.js

echo " msg2eml.bundle.js built and copied to public/libs/"
