import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import VoidGuard from './VoidGuard.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <VoidGuard />
  </StrictMode>
)