const { app, BrowserWindow } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn, spawnSync } = require('child_process');

let mainWindow;
let backendProcess;

function getBackendCommand() {
  if (app.isPackaged) {
    const packagedPath = path.join(process.resourcesPath, 'backend', 'backend.exe');
    return { command: packagedPath, args: [] };
  }

  const devPath = path.resolve(__dirname, '..', 'backend', 'dist', 'backend', 'backend.exe');
  if (fs.existsSync(devPath)) {
    return { command: devPath, args: [] };
  }

  if (process.platform === 'win32') {
    const pyCheck = spawnSync('py', ['-3', '--version'], { stdio: 'ignore' });
    if (pyCheck.status === 0) {
      return { command: 'py', args: ['-3', 'app.py'] };
    }

    const pythonCheck = spawnSync('python', ['--version'], { stdio: 'ignore' });
    if (pythonCheck.status === 0) {
      return { command: 'python', args: ['app.py'] };
    }
  }

  const python3Check = spawnSync('python3', ['--version'], { stdio: 'ignore' });
  if (python3Check.status === 0) {
    return { command: 'python3', args: ['app.py'] };
  }

  return { command: 'python', args: ['app.py'] };
}

function startBackend() {
  if (backendProcess) {
    return;
  }

  const backendDir = path.resolve(__dirname, '..', 'backend');
  const { command, args } = getBackendCommand();

  backendProcess = spawn(command, args, {
    cwd: backendDir,
    env: {
      ...process.env,
      PYTHONUNBUFFERED: '1',
      PYTHONIOENCODING: 'utf-8'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  backendProcess.stdout.on('data', (data) => {
    console.log(`[backend] ${data.toString()}`);
  });

  backendProcess.stderr.on('data', (data) => {
    console.error(`[backend] ${data.toString()}`);
  });

  backendProcess.on('exit', (code) => {
    if (!app.isQuitting) {
      console.log(`Backend process exited with code ${code}`);
    }
  });
}

function stopBackend() {
  if (backendProcess && !backendProcess.killed) {
    backendProcess.kill();
  }
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 1000,
    minWidth: 1200,
    minHeight: 800,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  const frontendPath = path.join(__dirname, '..', 'sceu_system', 'dist', 'index.html');

  setTimeout(() => {
    mainWindow.loadFile(frontendPath);
    mainWindow.once('ready-to-show', () => {
      mainWindow.show();
      mainWindow.webContents.openDevTools();
    });
  }, 1800);
}

app.whenReady().then(() => {
  startBackend();
  createWindow();
});

app.on('before-quit', () => {
  app.isQuitting = true;
  stopBackend();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});
