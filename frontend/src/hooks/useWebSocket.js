import { useEffect, useRef, useState, useCallback } from 'react'
import useAlertStore from '../store/alertStore'

const WS_URL = 'ws://localhost:8000/ws/live'
const RECONNECT_DELAY_MS = 3000
const MAX_RECONNECT_ATTEMPTS = 10

const useWebSocket = (url = WS_URL) => {
  const [connected, setConnected] = useState(false)
  const [error, setError] = useState(null)

  const wsRef = useRef(null)
  const reconnectTimerRef = useRef(null)
  const attemptsRef = useRef(0)
  const mountedRef = useRef(true)

  const { addAlert, addIncident, updateGraph, updateStats, setSimulationRunning } = useAlertStore()

  const handleMessage = useCallback(
    (event) => {
      try {
        const { type, data } = JSON.parse(event.data)
        switch (type) {
          case 'new_alert':
            addAlert(data)
            break
          case 'graph_update':
            updateGraph(data)
            break
          case 'new_incident':
            addIncident(data)
            break
          case 'stats_update':
            updateStats(data)
            // Auto-clear running flag when backend finishes all dataset files
            if (data.analysis_complete) {
              setSimulationRunning(false)
            }
            break
          case 'incident_update':
            useAlertStore.getState().updateAlertStatus(data.event_id, data.status)
            break
          default:
            console.warn('[WS] Unknown message type:', type)
        }
      } catch (err) {
        console.error('[WS] Failed to parse message:', err)
      }
    },
    [addAlert, addIncident, updateGraph, updateStats, setSimulationRunning]
  )

  const connect = useCallback(() => {
    if (!mountedRef.current) return
    if (attemptsRef.current >= MAX_RECONNECT_ATTEMPTS) {
      setError(`Max reconnect attempts (${MAX_RECONNECT_ATTEMPTS}) reached.`)
      return
    }

    try {
      const ws = new WebSocket(url)
      wsRef.current = ws

      ws.onopen = () => {
        if (!mountedRef.current) return
        attemptsRef.current = 0
        setConnected(true)
        setError(null)
        console.log('[WS] Connected to', url)
      }

      ws.onmessage = handleMessage

      ws.onerror = (e) => {
        console.error('[WS] Error:', e)
        setError('WebSocket connection error')
      }

      ws.onclose = (e) => {
        if (!mountedRef.current) return
        setConnected(false)
        console.warn(`[WS] Closed (code=${e.code}). Reconnecting in ${RECONNECT_DELAY_MS}ms...`)
        attemptsRef.current += 1
        reconnectTimerRef.current = setTimeout(connect, RECONNECT_DELAY_MS)
      }
    } catch (err) {
      setError(err.message)
    }
  }, [url, handleMessage])

  useEffect(() => {
    mountedRef.current = true
    connect()

    return () => {
      mountedRef.current = false
      clearTimeout(reconnectTimerRef.current)
      if (wsRef.current) {
        wsRef.current.onclose = null // prevent reconnect loop on unmount
        wsRef.current.close()
        wsRef.current = null
      }
    }
  }, [connect])

  return { connected, error }
}

export default useWebSocket
