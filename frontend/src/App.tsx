import { useState } from 'react';
import './App.css';

function App() {
  const [count, setCount] = useState(0);

  return (
    <>
      <div>
        <a href="/" target="_self">
          <img src="/favicon.svg" className="logo" alt="App logo" />
        </a>
        <a href="/" target="_self">
          <img
            src="/favicon-96x96.png"
            className="logo react"
            alt="App secondary logo"
          />
        </a>
      </div>
      <h1>Vite + React</h1>
      <div className="card">
        <button onClick={() => setCount((c) => c + 1)}>count is {count}</button>
        <p>
          Edit <code>src/App.tsx</code> and save to test HMR
        </p>
      </div>
      <p className="read-the-docs">Click on the logos above to go home</p>
    </>
  );
}

export default App;
