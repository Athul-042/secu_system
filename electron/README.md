# Electron Desktop Wrapper

This folder contains the desktop launcher for the intrusion detection project.

## What it does
- Starts the Flask backend automatically when the desktop app opens.
- Loads the React build inside an Electron window.
- Stops the backend process when the app closes.

## Run locally
1. Build the React frontend:
   - cd sceu_system
   - npm run build
2. Install Electron dependencies:
   - cd electron
   - npm install
3. Start the app:
   - npm start
