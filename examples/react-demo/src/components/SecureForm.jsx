import { useState, useCallback } from 'react'

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

function hexToBytes(hex) {
  const bytes = []
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16))
  }
  return new Uint8Array(bytes)
}

export default function SecureForm({ kemDem }) {
  const [keys, setKeys] = useState(null)
  const [fields, setFields] = useState([
    { name: 'ssn', value: '123-45-6789' },
    { name: 'dob', value: '1990-01-01' },
    { name: 'salary', value: '150000' },
  ])
  const [encryptedPackage, setEncryptedPackage] = useState(null)
  const [decryptedData, setDecryptedData] = useState(null)
  const [serializedPackage, setSerializedPackage] = useState('')
  const [error, setError] = useState(null)
  const [activeTab, setActiveTab] = useState('encrypt')

  const handleGenerateKeys = useCallback(() => {
    try {
      const kp = kemDem.generateKeypair()
      setKeys({
        publicKey: new Uint8Array(kp.publicKey),
        secretKey: new Uint8Array(kp.secretKey),
      })
      setError(null)
      setDecryptedData(null)
    } catch (err) {
      setError('Key generation failed: ' + err.message)
    }
  }, [kemDem])

  const handleFieldChange = useCallback((index, key, value) => {
    setFields((prev) => {
      const next = [...prev]
      next[index] = { ...next[index], [key]: value }
      return next
    })
  }, [])

  const handleAddField = useCallback(() => {
    setFields((prev) => [...prev, { name: '', value: '' }])
  }, [])

  const handleRemoveField = useCallback((index) => {
    setFields((prev) => prev.filter((_, i) => i !== index))
  }, [])

  const handleEncrypt = useCallback(() => {
    if (!keys) {
      setError('Generate keys first')
      return
    }
    try {
      const data = {}
      for (const f of fields) {
        if (f.name.trim()) {
          data[f.name] = f.value
        }
      }
      const pkg = kemDem.encryptFields(keys.publicKey, data)
      setEncryptedPackage(pkg)
      setDecryptedData(null)
      setActiveTab('encrypt')
      setError(null)

      // Serialize for display/storage
      const obj = pkg.toObject()
      const serialized = {
        kemCiphertext: bytesToHex(obj.kemCiphertext),
        encryptedFields: {},
      }
      const fieldNames = pkg.fieldNames()
      for (let i = 0; i < fieldNames.length; i++) {
        const name = fieldNames[i]
        const fieldBytes = pkg.getField(name)
        serialized.encryptedFields[name] = bytesToHex(fieldBytes)
      }
      setSerializedPackage(JSON.stringify(serialized, null, 2))
    } catch (err) {
      setError('Encryption failed: ' + err.message)
    }
  }, [kemDem, keys, fields])

  const handleDecrypt = useCallback(() => {
    if (!keys || !encryptedPackage) {
      setError('Encrypt data first')
      return
    }
    try {
      const plain = kemDem.decryptFields(keys.secretKey, encryptedPackage)
      setDecryptedData(plain)
      setActiveTab('decrypt')
      setError(null)
    } catch (err) {
      setError('Decryption failed: ' + (err.message || err))
    }
  }, [kemDem, keys, encryptedPackage])

  const handleLoadFromJson = useCallback(() => {
    try {
      const parsed = JSON.parse(serializedPackage)
      const kemCt = hexToBytes(parsed.kemCiphertext)
      const encFields = {}
      for (const [name, hex] of Object.entries(parsed.encryptedFields)) {
        encFields[name] = hexToBytes(hex)
      }
      const pkg = kemDem.constructor.prototype.constructor.new(kemCt, encFields)
      setEncryptedPackage(pkg)
      setDecryptedData(null)
      setError(null)
    } catch (err) {
      setError('Failed to load package: ' + err.message)
    }
  }, [serializedPackage, kemDem])

  return (
    <div className="secure-form">
      {error && (
        <div className="error-message">
          <span className="error-icon">!</span>
          {error}
          <button className="close-btn" onClick={() => setError(null)}>
            &times;
          </button>
        </div>
      )}

      <section className="card keys-section">
        <h2>1. Keypair</h2>
        <div className="key-actions">
          <button
            className="btn btn-primary"
            onClick={handleGenerateKeys}
            disabled={!kemDem}
          >
            Generate New Keypair
          </button>
        </div>
        {keys && (
          <div className="keys-display">
            <div className="key-row">
              <label>Public Key (32 bytes)</label>
              <code className="key-value">{bytesToHex(keys.publicKey)}</code>
            </div>
            <div className="key-row">
              <label>Secret Key (32 bytes)</label>
              <code className="key-value secret">{bytesToHex(keys.secretKey)}</code>
            </div>
          </div>
        )}
      </section>

      <section className="card fields-section">
        <h2>2. Fields to Encrypt</h2>
        <p className="hint">
          Add any number of fields. They are sealed under one HPKE session in deterministic field-name order.
        </p>
        <div className="fields-list">
          {fields.map((field, index) => (
            <div key={index} className="field-row">
              <input
                type="text"
                placeholder="Field name"
                value={field.name}
                onChange={(e) => handleFieldChange(index, 'name', e.target.value)}
                className="field-input field-name"
              />
              <input
                type="text"
                placeholder="Value"
                value={field.value}
                onChange={(e) => handleFieldChange(index, 'value', e.target.value)}
                className="field-input field-value"
              />
              <button
                className="btn btn-icon"
                onClick={() => handleRemoveField(index)}
                title="Remove field"
              >
                &minus;
              </button>
            </div>
          ))}
        </div>
        <button className="btn btn-secondary" onClick={handleAddField}>
          + Add Field
        </button>
      </section>

      <section className="card actions-section">
        <h2>3. Encrypt / Decrypt</h2>
        <div className="action-buttons">
          <button
            className="btn btn-primary"
            onClick={handleEncrypt}
            disabled={!keys}
          >
            Encrypt Fields
          </button>
          <button
            className="btn btn-primary"
            onClick={handleDecrypt}
            disabled={!keys || !encryptedPackage}
          >
            Decrypt Fields
          </button>
        </div>
      </section>

      {(encryptedPackage || decryptedData) && (
        <section className="card results-section">
          <div className="tabs">
            <button
              className={`tab ${activeTab === 'encrypt' ? 'active' : ''}`}
              onClick={() => setActiveTab('encrypt')}
            >
              Encrypted
            </button>
            <button
              className={`tab ${activeTab === 'decrypt' ? 'active' : ''}`}
              onClick={() => setActiveTab('decrypt')}
            >
              Decrypted
            </button>
            <button
              className={`tab ${activeTab === 'json' ? 'active' : ''}`}
              onClick={() => setActiveTab('json')}
            >
              Serialized JSON
            </button>
          </div>

          {activeTab === 'encrypt' && encryptedPackage && (
            <div className="result-panel">
              <h3>Encrypted Package</h3>
              <div className="data-row">
                <label>HPKE Encapsulated Key (32 bytes)</label>
              <code>{bytesToHex(encryptedPackage.kemCiphertext)}</code>
              </div>
              <div className="encrypted-fields">
                <label>Encrypted Fields</label>
                {(() => {
                  const names = encryptedPackage.fieldNames()
                  const items = []
                  for (let i = 0; i < names.length; i++) {
                    const name = names[i]
                    const bytes = encryptedPackage.getField(name)
                    items.push(
                      <div key={name} className="data-row">
                        <span className="field-label">{name}</span>
                        <code className="encrypted-value">
                          {bytesToHex(bytes).slice(0, 64)}...
                          ({bytes.length} bytes)
                        </code>
                      </div>
                    )
                  }
                  return items
                })()}
              </div>
            </div>
          )}

          {activeTab === 'decrypt' && (
            <div className="result-panel">
              <h3>Decrypted Data</h3>
              {decryptedData ? (
                <div className="decrypted-table">
                  {Object.entries(decryptedData).map(([key, value]) => (
                    <div key={key} className="data-row">
                      <span className="field-label">{key}</span>
                      <span className="field-plaintext">{value}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="placeholder">Click "Decrypt Fields" to see results</p>
              )}
            </div>
          )}

          {activeTab === 'json' && (
            <div className="result-panel">
              <h3>Serialized Package (JSON)</h3>
              <textarea
                className="json-editor"
                value={serializedPackage}
                onChange={(e) => setSerializedPackage(e.target.value)}
                rows={12}
              />
              <button className="btn btn-secondary" onClick={handleLoadFromJson}>
                Load from JSON
              </button>
            </div>
          )}
        </section>
      )}
    </div>
  )
}
