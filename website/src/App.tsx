import { HashRouter, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { HomePage } from "./pages/HomePage";
import { ProblemPage } from "./pages/ProblemPage";
import { AndroidPage } from "./pages/AndroidPage";
import { LibraryPage } from "./pages/LibraryPage";
import { UsagePage } from "./pages/UsagePage";
import { EvidencePage } from "./pages/EvidencePage";
import { NotFoundPage } from "./pages/NotFoundPage";

// Hash routing: GitHub Pages serves static files only, so a path like /usage
// would 404 on reload. The fragment keeps every route a request for
// index.html.
export function App() {
  return (
    <HashRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/problem" element={<ProblemPage />} />
          <Route path="/android" element={<AndroidPage />} />
          <Route path="/library" element={<LibraryPage />} />
          <Route path="/usage" element={<UsagePage />} />
          <Route path="/evidence" element={<EvidencePage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </Layout>
    </HashRouter>
  );
}
