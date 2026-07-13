import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";

import { AppShell } from "@/components/AppShell";
import { ProtectedRoute } from "@/components/ProtectedRoute";
import { AcceptInvitationPage } from "@/routes/AcceptInvitation";
import { AgentsPage } from "@/routes/Agents";
import { AuditPage } from "@/routes/Audit";
import { BansPage } from "@/routes/Bans";
import { ForgotPasswordPage } from "@/routes/ForgotPassword";
import { GraphPage } from "@/routes/Graph";
import { OrgMembersPage } from "@/routes/OrgMembers";
import { OrgSettingsPage } from "@/routes/OrgSettings";
import { OrgsPage } from "@/routes/Orgs";
import { PlaygroundPage } from "@/routes/Playground";
import { PoliciesPage } from "@/routes/Policies";
import { ResetPasswordPage } from "@/routes/ResetPassword";
import { SettingsPage } from "@/routes/Settings";
import { SignInPage } from "@/routes/SignIn";
import { SignUpPage } from "@/routes/SignUp";
import { TokensPage } from "@/routes/Tokens";
import { UsagePage } from "@/routes/Usage";
import { VerifyEmailPage } from "@/routes/VerifyEmail";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public auth routes — no shell, no auth required. Token-bearing
            URLs (verify-email, reset-password) live here so the email
            links land directly without bouncing through ProtectedRoute. */}
        <Route path="/sign-in" element={<SignInPage />} />
        <Route path="/sign-up" element={<SignUpPage />} />
        <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        <Route path="/reset-password/:token" element={<ResetPasswordPage />} />
        <Route path="/verify-email/:token" element={<VerifyEmailPage />} />

        {/* Public-but-auth-aware. The emailed magic-link lands here.
            The page itself handles the "you need to sign in" branch
            (it preserves the invite URL as ``state.from`` so SignIn
            bounces back here after login) — putting it inside
            ProtectedRoute would force the user to sign in BEFORE
            seeing what they're being invited to, which is hostile to
            the new-account-from-invite flow. */}
        <Route
          path="/invites/:inviteId/accept"
          element={<AcceptInvitationPage />}
        />

        {/* Authenticated dashboard. ProtectedRoute checks /v1/users/me
            and bounces signed-out visitors to /sign-in (preserving the
            requested path in state.from for post-sign-in redirect). */}
        <Route
          element={
            <ProtectedRoute>
              <AppShell />
            </ProtectedRoute>
          }
        >
          <Route index element={<Navigate to="/agents" replace />} />
          <Route path="agents" element={<AgentsPage />} />
          <Route path="policies" element={<PoliciesPage />} />
          <Route path="graph" element={<GraphPage />} />
          <Route path="playground" element={<PlaygroundPage />} />
          <Route path="audit" element={<AuditPage />} />
          <Route path="bans" element={<BansPage />} />
          <Route path="usage" element={<UsagePage />} />
          <Route path="tokens" element={<TokensPage />} />
          <Route path="orgs" element={<OrgsPage />} />
          <Route path="orgs/:orgId/settings" element={<OrgSettingsPage />} />
          <Route path="orgs/:orgId/members" element={<OrgMembersPage />} />
          <Route path="settings" element={<SettingsPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
