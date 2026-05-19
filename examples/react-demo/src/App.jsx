import { useState, useEffect } from 'react'
import init, { KemDem } from 'kem-dem-wasm'
import SecureForm from './components/SecureForm'
import './App.css'

function App() {
  const [wasmReady, setWasmReady] = useState(false)
  const [kemDem, setKemDem] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false

    async function loadWasm() {
      try {
        await init()
        if (cancelled) {
          return
        }

        setKemDem(new KemDem())
        setWasmReady(true)
      } catch (err) {
        console.error('Failed to initialize WASM:', err)
        if (!cancelled) {
          setError('Failed to initialize WASM module. Check console for details.')
        }
      }
    }

    loadWasm()

    return () => {
      cancelled = true
    }
  }, [])

  if (error) {
    return (
      <div className="app-container">
        <div className="error-banner">
          <h2>Error</h2>
          <p>{error}</p>
        </div>
      </div>
    )
  }

  if (!wasmReady) {
    return (
      <div className="app-container">
        <div className="loading">
          <div className="spinner" />
          <p>Loading KEM-DEM WASM module...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="app-container">
      <header className="app-header">
        <h1>KEM-DEM WASM Demo</h1>
        <p className="subtitle">
          HPKE-based hybrid encryption (RFC 9180) with per-field sealing
        </p>
      </header>
      <main>
        <SecureForm kemDem={kemDem} />
      </main>
      <footer className="app-footer">
        <p>
          Built with Rust/WASM + React. Uses HPKE (RFC 9180) with DHKEM(X25519, HKDF-SHA256) and AES-256-GCM.
        </p>
      </footer>
    </div>
  )
}

export default App
