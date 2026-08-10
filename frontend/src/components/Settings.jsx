import { useState, useEffect } from 'react'
import * as api from '../api'
import Adapters from './Adapters'

const PROVIDERS = [
  { value: 'ollama', label: 'Ollama (local, free, no key)' },
  { value: 'claude', label: 'Claude (Anthropic)' },
  { value: 'openai', label: 'OpenAI' },
  { value: 'gemini', label: 'Google Gemini' },
  { value: 'groq', label: 'Groq' },
]

export default function Settings({ onOpenHistory }) {
  const [info, setInfo] = useState(null)
  const [provider, setProvider] = useState('ollama')
  const [apiKey, setApiKey] = useState('')
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    api.getAiProvider().then(setInfo).catch((e) => setError(e.message))
  }, [])

  const save = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    setMessage('')
    try {
      const updated = await api.setAiProvider(provider, apiKey)
      setInfo(updated)
      setApiKey('')
      setMessage(`Provider switched to ${provider}.`)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  const remove = async (p) => {
    setLoading(true)
    setError('')
    try {
      await api.deleteAiProvider(p)
      setInfo({ provider: null, key_masked: '' })
      setMessage('Key deleted.')
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
    <div className="card">
      <div className="section-title">
        <h3>Scan History</h3>
        <button className="subtle" onClick={onOpenHistory}>🕘 View scan history</button>
      </div>
      <p className="status" style={{ marginBottom: 0 }}>Browse and reopen past scans in a popup.</p>
    </div>

    <Adapters />

    <div className="card">
      <h3 style={{ marginTop: 0 }}>AI Report Provider</h3>
      <p className="status">
        Keys are encrypted at rest in the local database and never returned in full or logged.
        Selecting Ollama keeps all data on this machine.
      </p>

      {info && info.provider && (
        <div className="row" style={{ marginBottom: 16 }}>
          <span className="status">Active provider:</span>
          <span className="pill info">{info.provider}</span>
          <span className="status">Key: {info.key_masked || 'n/a (Ollama)'}</span>
          <button className="ghost" onClick={() => remove(info.provider)} disabled={loading}>
            Delete key
          </button>
        </div>
      )}

      <form className="row" onSubmit={save}>
        <select value={provider} onChange={(e) => setProvider(e.target.value)}>
          {PROVIDERS.map((p) => (
            <option key={p.value} value={p.value}>
              {p.label}
            </option>
          ))}
        </select>
        {provider !== 'ollama' && (
          <input
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder="Paste API key"
            autoComplete="off"
          />
        )}
        <button className="primary" type="submit" disabled={loading}>
          {loading ? <span className="spinner" /> : 'Save'}
        </button>
      </form>

      {message && <p className="status">{message}</p>}
      {error && <div className="error">{error}</div>}
    </div>
    </>
  )
}
