import { Link } from "react-router-dom";

export function NotFound() {
  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center text-center">
      <p className="eyebrow text-signal">404</p>
      <h1 className="mt-4 font-display text-3xl font-semibold text-paper">Page not found.</h1>
      <p className="mt-2 text-sm text-mist-2">This console path doesn't exist.</p>
      <Link to="/" className="mt-6 text-sm text-signal underline-offset-4 hover:underline">
        Back to overview
      </Link>
    </div>
  );
}
