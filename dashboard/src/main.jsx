import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
import "./styles.css";

let data = null;
try { data = JSON.parse(document.getElementById("data").textContent); } catch { /* shown below */ }
createRoot(document.getElementById("root")).render(<App data={data} />);
