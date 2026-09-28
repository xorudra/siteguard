# What I need from Rudra to launch SiteGuard (step by step)

Project: **SiteGuard** (website security scanner).
This is a REAL request — not an example. Nothing below is done until you do these steps.

## Step 1 — Put the code on GitHub (FREE)
1. Go to github.com and log in (make a free account if you don't have one).
2. Click **New repository**, name it `siteguard`, leave it Public, click **Create**.
3. On your computer with git installed, run:
   ```
   cd ~/workspace/money-machines/security-scanner
   git init
   git add .
   git commit -m "SiteGuard v1"
   git branch -M main
   git remote add origin https://github.com/YOURNAME/siteguard.git
   git push -u origin main
   ```
   (Replace YOURNAME with your GitHub username.)

## Step 2 — Put it on the internet with Render (FREE)
1. Go to render.com, sign up free (you can sign up with your GitHub account).
2. Click **New +** -> **Web Service** -> connect your `siteguard` repo.
3. Render reads `render.yaml` in the repo and fills everything in by itself.
   If it asks: Build command = `pip install -r requirements.txt`,
   Start command = `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 60`.
4. Click **Create Web Service**. In ~2 minutes you get a public URL like
   `https://siteguard-xxxx.onrender.com`. Done — it's live.

## Step 3 (later, only when you say it's worthy) — Take payments
1. Razorpay account (FREE to start, they take a small cut per payment).
2. Tell me and I'll wire a "Pay Rs.499 -> unlock full report" button.
3. No subscriptions until you say so.

## Step 4 (optional, PAID ~Rs.800/year) — Your own domain
1. Buy a domain on Cloudflare or Porkbun.
2. In Render: Settings -> Custom Domain, follow their steps.
