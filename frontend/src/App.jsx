import React from 'react'
import Navbar from './components/Navbar'
import Dashboard from './pages/Dashboard'

function App() {
  return (
    <div className="min-h-screen bg-slate-950 flex flex-col font-sans">
      <Navbar />
      <Dashboard />
    </div>
  )
}

export default App
