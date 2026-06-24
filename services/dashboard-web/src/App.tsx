import { Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import AlertsPage from "./pages/AlertsPage";
import AlertDetailPage from "./pages/AlertDetailPage";
import ApprovalsPage from "./pages/ApprovalsPage";
import AttackPage from "./pages/AttackPage";
import EndpointsPage from "./pages/EndpointsPage";
import MetricsPage from "./pages/MetricsPage";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<AlertsPage />} />
        <Route path="/alert/:id" element={<AlertDetailPage />} />
        <Route path="/approvals" element={<ApprovalsPage />} />
        <Route path="/attack" element={<AttackPage />} />
        <Route path="/endpoints" element={<EndpointsPage />} />
        <Route path="/metrics" element={<MetricsPage />} />
      </Route>
    </Routes>
  );
}
