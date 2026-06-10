import { useState } from "react";
import axios from "axios";

function App() {

  const [url, setUrl] = useState("");
  const [result, setResult] = useState("");

  const checkURL = async () => {

    try {

      const response = await axios.post("http://127.0.0.1:5000/predict", {
        url: url
      });

      setResult(response.data.prediction);

    } catch (error) {

      console.error(error);
      setResult("Error connecting to server");

    }

  };

  return (
    <div style={{ textAlign: "center", marginTop: "100px" }}>

      <h1>NeuralShield 🔐</h1>
      <h3>Phishing Detection System</h3>

      <input
        type="text"
        placeholder="Enter URL"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        style={{ width: "300px", padding: "10px" }}
      />

      <br /><br />

      <button onClick={checkURL}>
        Check Website
      </button>

      <h2>{result}</h2>

    </div>
  );
}

export default App;