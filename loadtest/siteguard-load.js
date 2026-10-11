// SiteGuard load test — Launch Safety Standard G34.
//
// Run ONLY against a local instance or staging — NEVER production:
//
//   # local (boot the app the way render.yaml does, then):
//   gunicorn app:app --bind 127.0.0.1:5050 --workers 2 --timeout 120
//   k6 run loadtest/siteguard-load.js
//
//   # staging:
//   BASE_URL=https://siteguard-staging.onrender.com k6 run loadtest/siteguard-load.js
//
// Profile (tiny by design, <= 50 VUs, ~2 min):
//   pages      — ramps 0 -> 25 -> 50 VUs over the public GET pages
//                (home, privacy, terms, favicon). These are the cheap,
//                cacheable responses.
//   scan_probe — ONE virtual user repeatedly scanning example.com, to
//                observe the expensive path's behaviour alongside the
//                page load without tripping the by-design rate limit
//                (10 scans/hour per IP — bulk scan traffic would just
//                measure the limiter, not the app).
//
// Thresholds: failed page requests < 1%, page p95 < 800 ms.
import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE = __ENV.BASE_URL || 'http://127.0.0.1:5050';
const PAGES = ['/', '/privacy', '/terms', '/favicon.svg'];

// 429 from the scan endpoint is the rate limiter working as designed
// (10 scans/hour/IP), not a failure — count only real errors (5xx,
// network) against the failure thresholds. The GET pages never 429.
http.setResponseCallback(http.expectedStatuses(200, 429));

export const options = {
  scenarios: {
    pages: {
      executor: 'ramping-vus',
      exec: 'pages',
      startVUs: 0,
      stages: [
        { duration: '20s', target: 25 },
        { duration: '40s', target: 50 },
        { duration: '40s', target: 50 },
        { duration: '20s', target: 0 },
      ],
      gracefulRampDown: '10s',
    },
    scan_probe: {
      executor: 'constant-vus',
      exec: 'scanProbe',
      vus: 1,
      duration: '2m',
    },
  },
  thresholds: {
    'http_req_failed{scenario:pages}': ['rate<0.01'],
    'http_req_duration{scenario:pages}': ['p(95)<800'],
    'http_req_failed{scenario:scan_probe}': ['rate<0.05'],
  },
};

export function pages() {
  const page = PAGES[Math.floor(Math.random() * PAGES.length)];
  const res = http.get(`${BASE}${page}`, { tags: { scenario: 'pages' } });
  check(res, { 'page 200': (r) => r.status === 200 });
  sleep(1);
}

export function scanProbe() {
  const res = http.post(
    `${BASE}/scan`,
    { url: 'example.com' },
    { tags: { scenario: 'scan_probe' }, timeout: '120s' },
  );
  check(res, { 'scan 200 or 429 (limiter)': (r) => r.status === 200 || r.status === 429 });
  sleep(2);
}
