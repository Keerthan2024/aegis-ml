import { create } from 'zustand'

const useAlertStore = create((set, get) => ({
  alerts: [],
  incidents: [],
  graphData: { nodes: [], edges: [] },
  stats: {
    total_events: 0,
    events_per_second: 0,
    total_alerts: 0,
    alerts_by_severity: {},
    false_positive_rate: 0,
    current_file: null,
    analysis_complete: false,
  },
  simulationRunning: false,
  selectedIncident: null,

  addAlert: (alert) =>
    set((state) => ({
      alerts: [alert, ...state.alerts].slice(0, 200),
    })),

  addIncident: (inc) =>
    set((state) => ({
      incidents: [inc, ...state.incidents],
    })),

  updateGraph: (data) => set({ graphData: data }),

  // MERGE stats — partial WS updates won't wipe unrelated fields
  updateStats: (partial) =>
    set((state) => ({
      stats: { ...state.stats, ...partial },
    })),

  updateAlertStatus: (eventId, status) => set(state => ({
    alerts: state.alerts.map(a => a.event_id === eventId ? { ...a, status } : a)
  })),

  selectIncident: (id) => set({ selectedIncident: id }),

  setSimulationRunning: (val) => set({ simulationRunning: val }),

  clearAlerts: () =>
    set({
      alerts: [],
      incidents: [],
      stats: {
        total_events: 0,
        events_per_second: 0,
        total_alerts: 0,
        alerts_by_severity: {},
        false_positive_rate: 0,
        current_file: null,
        analysis_complete: false,
      },
    }),
}))

export default useAlertStore
