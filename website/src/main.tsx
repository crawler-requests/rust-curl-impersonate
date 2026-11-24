import React from "react";
import ReactDOM from "react-dom/client";
import { ConfigProvider } from "antd";
import { App } from "./App";
import { antdTheme } from "./theme/antd";
import "./styles/global.css";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <ConfigProvider theme={antdTheme}>
      <App />
    </ConfigProvider>
  </React.StrictMode>,
);
