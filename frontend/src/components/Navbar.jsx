import React from 'react';

export default function Navbar() {
  return (
    <nav className="bg-slate-900 border-b border-slate-800 px-6 py-4 flex items-center justify-between text-white shadow-md">
      <div className="flex items-center space-x-3">
        <span className="text-xl font-bold bg-gradient-to-r from-blue-400 to-indigo-500 bg-clip-text text-transparent">
          🛡️ PhishGuard AI
        </span>
      </div>
      <div className="flex items-center space-x-4 text-sm font-medium text-slate-300">
        <span className="hover:text-white cursor-pointer transition">Dashboard</span>
        <span className="hover:text-white cursor-pointer transition">URL Scanner</span>
        <span className="hover:text-white cursor-pointer transition">Threat Intel</span>
      </div>
    </nav>
  );
}
