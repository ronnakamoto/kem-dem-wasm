import { useState, useCallback, useEffect } from 'react'
import { HDNodeWallet } from 'ethers'

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

function hexToBytes(hex) {
  let clean = String(hex).trim().replace(/^0x/i, '')
  if (clean.length === 0) {
    return new Uint8Array()
  }
  if (!/^[0-9a-fA-F]+$/.test(clean)) {
    throw new Error('Invalid hex string')
  }
  if (clean.length % 2 !== 0) {
    clean = '0' + clean
  }
  const bytes = new Uint8Array(clean.length / 2)
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.slice(i, i + 2), 16)
  }
  return bytes
}

export default function SecureForm({ kemDem, zkEncryptor, EncryptedPackage }) {
  const [keys, setKeys] = useState(null)
  const [keyGenMode, setKeyGenMode] = useState('random') // 'random' | 'ikm' | 'signature'
  
  // Test vector pre-fills
  const [ikmHex, setIkmHex] = useState('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20')
  const [addressHex, setAddressHex] = useState('d8da6bf26964af9d7eed9e03e53415d37aa96045')
  const [sigHex, setSigHex] = useState('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011b')
  
  const [walletAddress, setWalletAddress] = useState('')
  const [walletConnected, setWalletConnected] = useState(false)
  const [signatureMethod, setSignatureMethod] = useState('')

  // Mnemonic and HD derivation states
  const [mnemonic, setMnemonic] = useState('test test test test test test test test test test test junk')
  const [derivationPath, setDerivationPath] = useState(() => {
    try {
      return kemDem.constructor.encryptionDerivationPath()
    } catch {
      return "m/44'/60'/0'/2147483647'/0"
    }
  })
  const [derivationError, setDerivationError] = useState(null)

  // Dynamically derive IKM and Address when mnemonic/path changes
  useEffect(() => {
    if (keyGenMode === 'ikm') {
      try {
        const cleanMnemonic = mnemonic.trim().toLowerCase().replace(/\s+/g, ' ')
        const words = cleanMnemonic.split(' ')
        if (words.length < 12) {
          setDerivationError('Mnemonic must be at least 12 words')
          return
        }
        // ethers v6 fromPhrase derives the default 'm/44'/60'/0'/0/0' path if no path is given.
        // We supply our custom path directly here (phrase, password, path).
        const child = HDNodeWallet.fromPhrase(cleanMnemonic, "", derivationPath.trim())
        setIkmHex(child.privateKey.replace(/^0x/, ''))
        setAddressHex(child.address.toLowerCase().replace(/^0x/, ''))
        setDerivationError(null)
      } catch (err) {
        setDerivationError(err.message)
      }
    }
  }, [mnemonic, derivationPath, keyGenMode])

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
  const [zkCiphertext, setZkCiphertext] = useState(null)
  const [zkDecryptedData, setZkDecryptedData] = useState(null)
  const [zkKeypair, setZkKeypair] = useState(() => {
    try { return window.__zkKeypair || null } catch { return null }
  })
  const [algorithm, setAlgorithm] = useState('hpke')

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

  const handleDeriveFromIkm = useCallback(() => {
    try {
      const cleanIkm = hexToBytes(ikmHex.trim().replace(/^0x/, ''))
      const cleanAddr = hexToBytes(addressHex.trim().replace(/^0x/, ''))
      const kp = kemDem.deriveKeypairFromIkm(cleanIkm, cleanAddr)
      setKeys({
        publicKey: new Uint8Array(kp.publicKey),
        secretKey: new Uint8Array(kp.secretKey),
      })
      setError(null)
      setDecryptedData(null)
    } catch (err) {
      setError('IKM derivation failed: ' + err.message)
    }
  }, [kemDem, ikmHex, addressHex])

  const handleDeriveFromSignature = useCallback(() => {
    try {
      const cleanSig = hexToBytes(sigHex.trim().replace(/^0x/, ''))
      const cleanAddr = hexToBytes(addressHex.trim().replace(/^0x/, ''))
      const kp = kemDem.deriveKeypairFromSignature(cleanSig, cleanAddr)
      setKeys({
        publicKey: new Uint8Array(kp.publicKey),
        secretKey: new Uint8Array(kp.secretKey),
      })
      setError(null)
      setDecryptedData(null)
    } catch (err) {
      setError('Signature derivation failed: ' + err.message)
    }
  }, [kemDem, sigHex, addressHex])

  const handleConnectAndSign = useCallback(async () => {
    if (!window.ethereum) {
      setError('MetaMask or injected EIP-1193 wallet not found. Please install a wallet extension.')
      return
    }
    try {
      const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' })
      if (!accounts || accounts.length === 0) {
        throw new Error('No accounts selected')
      }
      const addr = accounts[0]
      setWalletAddress(addr)
      setWalletConnected(true)

      let sig = ''
      try {
        const chainIdHex = await window.ethereum.request({ method: 'eth_chainId' })
        const chainId = Number(BigInt(chainIdHex))
        const path = kemDem.constructor.encryptionDerivationPath()
        const typedData = {
          types: {
            EIP712Domain: [
              { name: 'name', type: 'string' },
              { name: 'version', type: 'string' },
              { name: 'chainId', type: 'uint256' },
            ],
            KemDemDerive: [
              { name: 'action', type: 'string' },
              { name: 'path', type: 'string' },
            ],
          },
          primaryType: 'KemDemDerive',
          domain: {
            name: 'kem-dem-wasm',
            version: '1',
            chainId,
          },
          message: {
            action: 'derive-encryption-key',
            path,
          },
        }
        sig = await window.ethereum.request({
          method: 'eth_signTypedData_v4',
          params: [addr, JSON.stringify(typedData)],
        })
        setSignatureMethod('eip712')
      } catch {
        const message = 'kem-dem-wasm/v1/derive-encryption-key'
        sig = await window.ethereum.request({
          method: 'personal_sign',
          params: [message, addr],
        })
        setSignatureMethod('personal_sign')
      }

      const cleanSig = hexToBytes(sig.replace(/^0x/, ''))
      const cleanAddr = hexToBytes(addr.replace(/^0x/, ''))
      const kp = kemDem.deriveKeypairFromSignature(cleanSig, cleanAddr)

      setKeys({
        publicKey: new Uint8Array(kp.publicKey),
        secretKey: new Uint8Array(kp.secretKey),
      })

      setAddressHex(addr.replace(/^0x/, ''))
      setSigHex(sig.replace(/^0x/, ''))
      setKeyGenMode('signature')
      setError(null)
      setDecryptedData(null)
    } catch (err) {
      setError('Wallet signature failed: ' + (err.message || err))
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
    if (algorithm === 'zk') {
      try {
        const normalizeHex = (s) => {
          if (typeof s !== 'string') s = String(s)
          s = s.trim()
          const hasPrefix = s.startsWith('0x') || s.startsWith('0X')
          let clean = hasPrefix ? s.slice(2) : s
          clean = clean.trim()
          if (clean.length === 0) clean = '00'
          if (!/^[0-9a-fA-F]+$/.test(clean)) {
            throw new Error('Invalid hex string')
          }
          if (clean.length % 2 !== 0) clean = '0' + clean
          if (clean.length > 64) {
            throw new Error('ZK payload hex must be ≤ 32 bytes')
          }
          clean = clean.toLowerCase().padStart(64, '0')
          return '0x' + clean
        }

        const encodeUtf8ToFrHex = (value) => {
          const bytes = new TextEncoder().encode(value)
          if (bytes.length > 31) {
            throw new Error('ZK text payload must be ≤ 31 bytes (or provide a 0x-prefixed Fr hex)')
          }
          const out = new Uint8Array(32)
          out.set(bytes, 1)
          return '0x' + Array.from(out).map((b) => b.toString(16).padStart(2, '0')).join('')
        }

        const payloadHex = fields.map(f => {
          if (f.value.startsWith('0x')) {
            return normalizeHex(f.value)
          }
          return encodeUtf8ToFrHex(f.value)
        })
        const xHex = zkKeypair?.publicKey?.x;
        const yHex = zkKeypair?.publicKey?.y;
        if (!xHex || !yHex) {
          throw new Error('ZK public key not available')
        }
        if (typeof xHex !== 'string' || typeof yHex !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(xHex) || !/^0x[0-9a-fA-F]{64}$/.test(yHex)) {
          throw new Error('ZK public key must be 0x-prefixed 32-byte hex (x,y)')
        }
        // Authenticated DEM: appends a Poseidon MAC tag bound to the
        // shared secret and ephemeral public key. Decrypt verifies the
        // tag in constant time before returning plaintext. Recommended
        // for any data not consumed inside a SNARK that itself enforces
        // integrity.
        const ciphertext = zkEncryptor.encryptAuthenticated(xHex, yHex, payloadHex)
        setZkCiphertext(ciphertext)
        setActiveTab('zk')
        setError(null)
      } catch (err) {
        setError('ZK encryption failed: ' + (err.message || err))
      }
      return
    }

    if (!keys) {
      setError('Generate or derive keys first')
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
  }, [kemDem, zkEncryptor, keys, fields, algorithm])

  const handleDecrypt = useCallback(() => {
    if (algorithm === 'zk') {
      try {
        if (!zkCiphertext) {
          setError('Encrypt with ZK first')
          return
        }
        const secKey = zkKeypair?.secretKey || ''
        if (!secKey) {
          setError('ZK keypair not available')
          return
        }
        // Authenticated path: verifies the Poseidon MAC tag (constant
        // time) before returning plaintext. Throws on tampering or
        // wrong-key. Must match `encryptAuthenticated` used in
        // `handleEncrypt`.
        const decryptedFrArray = zkEncryptor.decryptAuthenticated(secKey, zkCiphertext)
        const decoded = []
        for (let i = 0; i < decryptedFrArray.length; i++) {
          const hexStr = decryptedFrArray[i]
          const clean = hexStr.replace(/^0x/, '')
          const bytes = hexToBytes(clean)
          const text = new TextDecoder().decode(bytes)
          decoded.push({ index: i, hex: hexStr, text: text.replace(/\0+$/g, '') })
        }
        setZkDecryptedData(decoded)
        setActiveTab('zk-decrypt')
        setError(null)
      } catch (err) {
        setError('ZK Decryption failed: ' + (err.message || err))
      }
      return
    }
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
  }, [kemDem, zkEncryptor, keys, encryptedPackage, algorithm, zkCiphertext, zkKeypair])

  const handleLoadFromJson = useCallback(() => {
    try {
      const parsed = JSON.parse(serializedPackage)
      const kemCt = hexToBytes(parsed.kemCiphertext)
      const encFields = {}
      for (const [name, hex] of Object.entries(parsed.encryptedFields)) {
        encFields[name] = hexToBytes(hex)
      }
      // Reconstruct via the wasm-bindgen `EncryptedPackage` constructor.
      // This is the correct round-trip: serialize via `pkg.toObject()` /
      // `bytesToHex(...)`, then rehydrate via `new EncryptedPackage(...)`.
      const pkg = new EncryptedPackage(kemCt, encFields)
      setEncryptedPackage(pkg)
      setDecryptedData(null)
      setError(null)
    } catch (err) {
      setError('Failed to load package: ' + err.message)
    }
  }, [serializedPackage, EncryptedPackage])

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
        <h2>1. Encryption Keypair Source</h2>
        
        <div className="mode-selector">
          <button
            className={`mode-btn ${keyGenMode === 'random' ? 'active' : ''}`}
            onClick={() => setKeyGenMode('random')}
          >
            Random (generateKeypair)
          </button>
          <button
            className={`mode-btn ${keyGenMode === 'ikm' ? 'active' : ''}`}
            onClick={() => setKeyGenMode('ikm')}
          >
            Seed/IKM (BIP-32)
          </button>
          <button
            className={`mode-btn ${keyGenMode === 'signature' ? 'active' : ''}`}
            onClick={() => setKeyGenMode('signature')}
          >
            Signature (EIP-191)
          </button>
        </div>

        {keyGenMode === 'random' && (
          <div className="key-actions">
            <p className="hint">Generates a cryptographically secure random Curve25519 keypair locally.</p>
            <button
              className="btn btn-primary"
              onClick={handleGenerateKeys}
              disabled={!kemDem}
            >
              Generate Random Keypair
            </button>
          </div>
        )}

        {keyGenMode === 'ikm' && (
          <div className="mode-inputs">
            <p className="hint">
              Derives a deterministic keypair from a BIP-39 mnemonic seed phrase using standard hierarchical derivation (BIP-32).
            </p>
            
            <div className="input-group">
              <label>Mnemonic Seed Phrase (12 or 24 words)</label>
              <textarea
                className="field-input json-editor"
                style={{ height: '70px', fontFamily: 'inherit', fontSize: '0.875rem', resize: 'none' }}
                value={mnemonic}
                onChange={(e) => setMnemonic(e.target.value)}
                placeholder="Enter your 12 or 24-word seed phrase"
              />
            </div>
            
            <div className="input-group">
              <label>Derivation Path</label>
              <input
                type="text"
                value={derivationPath}
                onChange={(e) => setDerivationPath(e.target.value)}
                placeholder="e.g. m/44'/60'/0'/2147483647'/0"
              />
            </div>

            {derivationError && (
              <div className="derivation-error" style={{ color: '#f87171', fontSize: '0.8125rem', display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                <span>⚠️</span> {derivationError}
              </div>
            )}

            <div style={{ margin: '0.5rem 0', borderTop: '1px solid var(--border)', paddingTop: '0.75rem' }}>
              <h4 style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.5rem' }}>
                Auto-derived parameters
              </h4>
              
              <div className="input-group" style={{ marginBottom: '0.75rem' }}>
                <label>Derived Input Keying Material (IKM Hex)</label>
                <input
                   type="text"
                   value={ikmHex}
                   readOnly
                   style={{ opacity: 0.7, cursor: 'not-allowed', background: 'rgba(0,0,0,0.2)' }}
                 />
              </div>
              
              <div className="input-group">
                <label>Derived Ethereum Address</label>
                <input
                  type="text"
                  value={'0x' + addressHex}
                  readOnly
                  style={{ opacity: 0.7, cursor: 'not-allowed', background: 'rgba(0,0,0,0.2)' }}
                />
              </div>
            </div>

            <button
              className="btn btn-primary"
              onClick={handleDeriveFromIkm}
              disabled={!kemDem || !!derivationError || !ikmHex || !addressHex}
              style={{ marginTop: '0.5rem' }}
            >
              Derive Deterministic Keypair
            </button>
          </div>
        )}

        {keyGenMode === 'signature' && (
          <div className="mode-inputs">
            <p className="hint">Derives a deterministic keypair from an Ethereum signature and address. Zero-seed exposure.</p>
            
            {window.ethereum && (
              <div style={{ marginBottom: '1rem' }}>
                <button
                  className="btn btn-secondary"
                  onClick={handleConnectAndSign}
                  disabled={!kemDem}
                >
                  ⚡ Connect Wallet & Sign Prompt
                </button>
                {walletConnected && (
                  <div className="wallet-status">
                    <span className="wallet-status-dot"></span>
                    Connected to {walletAddress.slice(0, 6)}...{walletAddress.slice(-4)}{signatureMethod ? ` (${signatureMethod})` : ''}
                  </div>
                )}
              </div>
            )}
            
            <div className="input-group">
              <label>Signature (65 bytes Hex)</label>
              <input
                type="text"
                value={sigHex}
                onChange={(e) => setSigHex(e.target.value)}
                placeholder="65 bytes signature hex value"
              />
            </div>
            
            <div className="input-group">
              <label>Ethereum Address (20 bytes Hex)</label>
              <input
                type="text"
                value={addressHex}
                onChange={(e) => setAddressHex(e.target.value)}
                placeholder="20 bytes address hex value"
              />
            </div>

            <button
              className="btn btn-primary"
              onClick={handleDeriveFromSignature}
              disabled={!kemDem || !sigHex || !addressHex}
              style={{ marginTop: '0.5rem' }}
            >
              Derive Keypair from Signature
            </button>
          </div>
        )}

        {keys && (
          <div className="keys-display" style={{ marginTop: '1rem' }}>
            <div className="key-row">
              <label>Derived Public Key (32 bytes)</label>
              <code className="key-value">{bytesToHex(keys.publicKey)}</code>
            </div>
            <div className="key-row">
              <label>Derived Secret Key (32 bytes)</label>
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
        
        <div className="mode-selector" style={{ marginBottom: '1.5rem' }}>
          <button
            className={`mode-btn ${algorithm === 'hpke' ? 'active' : ''}`}
            onClick={() => setAlgorithm('hpke')}
          >
            HPKE (Standard)
          </button>
          <button
            className={`mode-btn ${algorithm === 'zk' ? 'active' : ''}`}
            onClick={() => setAlgorithm('zk')}
          >
            ZK Encryption (BabyJubJub)
          </button>
        </div>

        {algorithm === 'zk' && zkKeypair && (
          <div className="input-group" style={{ marginBottom: '1rem' }}>
            <label>ZK Keypair (auto-generated)</label>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              <code style={{ fontSize: '0.75rem', wordBreak: 'break-all', flex: '1 1 100%' }}>
                Pub X: {zkKeypair.publicKey?.x}
              </code>
              <code style={{ fontSize: '0.75rem', wordBreak: 'break-all', flex: '1 1 100%' }}>
                Pub Y: {zkKeypair.publicKey?.y}
              </code>
            </div>
          </div>
        )}

        <div className="action-buttons">
          <button
            className="btn btn-primary"
            onClick={handleEncrypt}
            disabled={fields.length === 0 || (algorithm === 'hpke' && !keys)}
          >
            Encrypt Fields
          </button>
          <button
            className="btn btn-primary"
            onClick={handleDecrypt}
            disabled={(algorithm === 'hpke' && (!keys || !encryptedPackage)) || (algorithm === 'zk' && !zkCiphertext)}
          >
            {algorithm === 'zk' ? 'Decrypt ZK' : 'Decrypt Fields'}
          </button>
        </div>
      </section>

      {(encryptedPackage || decryptedData || zkCiphertext) && (
        <section className="card results-section">
          <div className="tabs">
            <button
              className={`tab ${activeTab === 'encrypt' ? 'active' : ''}`}
              onClick={() => setActiveTab('encrypt')}
            >
              HPKE Encrypted
            </button>
            <button
              className={`tab ${activeTab === 'decrypt' ? 'active' : ''}`}
              onClick={() => setActiveTab('decrypt')}
            >
              HPKE Decrypted
            </button>
            <button
              className={`tab ${activeTab === 'zk' ? 'active' : ''}`}
              onClick={() => setActiveTab('zk')}
            >
              ZK Ciphertext (Fr254)
            </button>
            <button
              className={`tab ${activeTab === 'zk-decrypt' ? 'active' : ''}`}
              onClick={() => setActiveTab('zk-decrypt')}
            >
              ZK Decrypted
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

          {activeTab === 'zk' && zkCiphertext && (
            <div className="result-panel">
              <h3>ZK Ciphertext (BabyJubJub KEM-DEM, authenticated)</h3>
              <p className="hint">
                Exactly <strong>{zkCiphertext.length} hex characters</strong> ({(zkCiphertext.length / 2)} bytes).<br/>
                Represents {fields.length} payload Fr254 elements + 2 ephemeral key components + 1 Poseidon MAC tag.
              </p>
              <textarea
                className="json-editor"
                value={zkCiphertext}
                readOnly
                rows={8}
                style={{ wordBreak: 'break-all', fontFamily: 'monospace' }}
              />
            </div>
          )}

          {activeTab === 'zk-decrypt' && (
            <div className="result-panel">
              <h3>ZK Decrypted Payload</h3>
              {zkDecryptedData ? (
                <div className="decrypted-table">
                  {zkDecryptedData.map((item) => (
                    <div key={item.index} className="data-row">
                      <span className="field-label">Field {item.index}</span>
                      <code className="encrypted-value" style={{ fontSize: '0.75rem' }}>{item.hex}</code>
                      <span className="field-plaintext">{item.text}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="placeholder">Click "Decrypt ZK" to decrypt with the auto-generated keypair</p>
              )}
            </div>
          )}
        </section>
      )}
    </div>
  )
}
