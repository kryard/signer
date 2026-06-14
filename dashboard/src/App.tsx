import { lazy, Suspense, type ComponentType } from "react";
import { Routes, Route } from "react-router-dom";
import { OrgProvider } from "@/context/OrgContext";
import { Shell } from "@/components/Shell";
import { Loading } from "@/components/ui/Feedback";

// Route-level code splitting: each page loads on demand, which keeps the
// crypto-heavy chunks (viem + noble in Sign) out of the first paint.
const Overview = lazy(() => import("@/pages/Overview").then((m) => ({ default: m.Overview })));
const Wallets = lazy(() => import("@/pages/Wallets").then((m) => ({ default: m.Wallets })));
const WalletDetail = lazy(() =>
  import("@/pages/WalletDetail").then((m) => ({ default: m.WalletDetail })),
);
const Policies = lazy(() => import("@/pages/Policies").then((m) => ({ default: m.Policies })));
const Activities = lazy(() =>
  import("@/pages/Activities").then((m) => ({ default: m.Activities })),
);
const ActivityDetail = lazy(() =>
  import("@/pages/ActivityDetail").then((m) => ({ default: m.ActivityDetail })),
);
const Keys = lazy(() => import("@/pages/Keys").then((m) => ({ default: m.Keys })));
const Sign = lazy(() => import("@/pages/Sign").then((m) => ({ default: m.Sign })));
const Settings = lazy(() => import("@/pages/Settings").then((m) => ({ default: m.Settings })));
const Profile = lazy(() => import("@/pages/Profile").then((m) => ({ default: m.Profile })));
const NotFound = lazy(() => import("@/pages/NotFound").then((m) => ({ default: m.NotFound })));

function el(Page: ComponentType) {
  return (
    <Suspense fallback={<Loading />}>
      <Page />
    </Suspense>
  );
}

function App() {
  return (
    <OrgProvider>
      <Routes>
        <Route element={<Shell />}>
          <Route index element={el(Overview)} />
          <Route path="wallets" element={el(Wallets)} />
          <Route path="wallets/:id" element={el(WalletDetail)} />
          <Route path="policies" element={el(Policies)} />
          <Route path="activities" element={el(Activities)} />
          <Route path="activities/:id" element={el(ActivityDetail)} />
          <Route path="keys" element={el(Keys)} />
          <Route path="sign" element={el(Sign)} />
          <Route path="settings" element={el(Settings)} />
          <Route path="profile" element={el(Profile)} />
          <Route path="*" element={el(NotFound)} />
        </Route>
      </Routes>
    </OrgProvider>
  );
}

export default App;
