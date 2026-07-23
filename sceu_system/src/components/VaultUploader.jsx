import { useState, useEffect } from 'react';

const getBackendUrl = () => {
  if (window.electronAPI?.getBackendUrl) {
    return window.electronAPI.getBackendUrl();
  }
  return window.location.hostname === 'localhost'
    ? 'http://localhost:5000'
    : `http://${window.location.hostname}:5000`;
};

const formatBytes = (bytes) => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
};

const VaultUploader = () => {
  const BACKEND_URL = getBackendUrl();
  const [file, setFile] = useState(null);
  const [status, setStatus] = useState(null);
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(false);
  const [downloadLoading, setDownloadLoading] = useState(null);

  const allowedExtensions = ['pdf', 'docx', 'txt', 'png', 'jpg', 'jpeg', 'gif'];
  const maxSize = 100 * 1024 * 1024;

  useEffect(() => {
    fetchFileList();
  }, []);

  const fetchFileList = async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/vault/files/list`);
      if (!res.ok) {
        setStatus('Unable to load file list.');
        setFiles([]);
        return;
      }
      const data = await res.json();
      setFiles(data.files || []);
      setStatus('');
    } catch (err) {
      setStatus('Network error while loading files.');
    }
  };

  const handleFileChange = (event) => {
    const selected = event.target.files[0];
    if (!selected) {
      setFile(null);
      return;
    }
    const ext = selected.name.split('.').pop().toLowerCase();
    if (!allowedExtensions.includes(ext)) {
      setStatus(`Invalid file type. Allowed: ${allowedExtensions.join(', ')}`);
      setFile(null);
      return;
    }
    if (selected.size > maxSize) {
      setStatus('File too large. Max is 100 MB.');
      setFile(null);
      return;
    }
    setFile(selected);
    setStatus(null);
  };

  const handleUpload = async (event) => {
    event.preventDefault();
    if (!file) {
      setStatus('Please select a valid file.');
      return;
    }

    const formData = new FormData();
    formData.append('file', file);

    setLoading(true);
    setStatus('Uploading file...');

    try {
      const res = await fetch(`${BACKEND_URL}/vault/files/upload`, {
        method: 'POST',
        body: formData
      });
      const data = await res.json();
      if (!res.ok) {
        setStatus(data.error || 'Upload failed.');
      } else {
        setStatus(`Uploaded successfully. File ID: ${data.file_id}`);
        setFile(null);
        document.getElementById('vault-file-input').value = '';
        fetchFileList();
      }
    } catch (err) {
      setStatus('Upload failed due to network error.');
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async (fileId, filename) => {
    setDownloadLoading(fileId);
    try {
      const res = await fetch(`${BACKEND_URL}/vault/files/download/${fileId}`);
      if (!res.ok) {
        const err = await res.json();
        setStatus(err.error || 'Download failed.');
        setDownloadLoading(null);
        return;
      }
      const blob = await res.blob();
      const link = document.createElement('a');
      link.href = window.URL.createObjectURL(blob);
      link.download = `${filename}.enc`;
      link.click();
      setStatus(`Downloaded encrypted file: ${filename}.enc`);
    } catch (err) {
      setStatus('Download failed due to network error.');
    } finally {
      setDownloadLoading(null);
    }
  };

  return (
    <div className="dashboard-card" style={{ minHeight: 'fit-content' }}>
      <div className="card-header">
        <div>
          <h3 className="card-title">Protected File Vault</h3>
          <p style={{ color: '#94a3b8', marginTop: '8px', fontSize: '0.92rem' }}>
            Upload confidential files and keep them encrypted on the server.
          </p>
        </div>
      </div>

      <form onSubmit={handleUpload} style={{ display: 'grid', gap: '16px' }}>
        <div style={{ display: 'grid', gap: '8px' }}>
          <label style={{ color: '#cbd5e1', fontSize: '0.9rem' }}>Choose a confidential file</label>
          <label style={{ color: '#cbd5e1', fontSize: '0.9rem' }}>Select file</label>
          <input
            id="vault-file-input"
            type="file"
            onChange={handleFileChange}
            style={{ color: '#f8fafc' }}
          />
          {file && (
            <div style={{ color: '#94a3b8', fontSize: '0.85rem' }}>
              {file.name} • {formatBytes(file.size)}
            </div>
          )}
        </div>

        <button
          type="submit"
          className="scan-button"
          disabled={loading}
          style={{ width: '100%' }}
        >
          {loading ? 'Uploading...' : 'Upload and Encrypt'}
        </button>
      </form>

      <div style={{ marginTop: '20px', display: 'grid', gap: '12px' }}>
        <div style={{ fontSize: '0.85rem', color: '#94a3b8' }}>
          Allowed: pdf, docx, txt, png, jpg, jpeg, gif. Max 100 MB. Only encrypted file stored on server.
        </div>
        {status && (
          <div style={{ color: status.startsWith('Uploaded') ? '#34d399' : '#fca5a5', fontSize: '0.95rem' }}>
            {status}
          </div>
        )}
      </div>

      <div style={{ marginTop: '24px' }}>
        <h4 style={{ marginBottom: '12px', color: '#f8fafc' }}>Your Uploaded Files</h4>
        <div style={{ maxHeight: '220px', overflowY: 'auto' }}>
          {files.length === 0 ? (
            <div style={{ color: '#94a3b8', fontSize: '0.9rem' }}>No uploaded files yet.</div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.9rem' }}>
              <thead>
                <tr style={{ textAlign: 'left', borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
                  <th style={{ padding: '10px 8px', color: '#94a3b8' }}>Filename</th>
                  <th style={{ padding: '10px 8px', color: '#94a3b8' }}>Size</th>
                  <th style={{ padding: '10px 8px', color: '#94a3b8' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {files.map((fileItem) => (
                  <tr key={fileItem.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                    <td style={{ padding: '10px 8px', color: '#e2e8f0' }}>{fileItem.original_filename}</td>
                    <td style={{ padding: '10px 8px', color: '#94a3b8' }}>{formatBytes(fileItem.size)}</td>
                    <td style={{ padding: '10px 8px' }}>
                      <button
                        onClick={() => handleDownload(fileItem.id, fileItem.original_filename)}
                        disabled={downloadLoading === fileItem.id}
                        style={{
                          background: '#2563eb',
                          color: '#fff',
                          border: 'none',
                          borderRadius: '10px',
                          padding: '8px 12px',
                          cursor: 'pointer'
                        }}
                      >
                        {downloadLoading === fileItem.id ? 'Downloading...' : 'Download'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
};

export default VaultUploader;
