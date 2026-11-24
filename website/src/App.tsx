import { HashRouter, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { HomePage } from "./pages/HomePage";
import { ProblemPage } from "./pages/ProblemPage";
import { AndroidPage } from "./pages/AndroidPage";
import { LibraryPage } from "./pages/LibraryPage";
import { UsagePage } from "./pages/UsagePage";
import { EvidencePage } from "./pages/EvidencePage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { ClientsPage } from "./pages/ClientsPage";
import { FamilyPage } from "./pages/FamilyPage";
import { FAMILY_PAGES } from "./data/families";

// Hash routing: GitHub Pages serves static files only, so a path like /usage
// would 404 on reload. The fragment keeps every route a request for
// index.html.
//
// One route per client family, generated from FAMILY_PAGES so the nav and the
// routes cannot drift apart. Android has its own page beyond the family
// listing, because it needed to explain the four stacks at length.
export function App() {
  const families = FAMILY_PAGES.filter((page) => page.key !== "android");

  return (
    <HashRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/problem" element={<ProblemPage />} />
          <Route path="/clients" element={<ClientsPage />} />
          {families.map((page) => (
            <Route key={page.key} path={page.path} element={<FamilyPage spec={page} />} />
          ))}
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
